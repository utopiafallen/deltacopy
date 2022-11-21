#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#include <Windows.h>
#include <Shlwapi.h>

#include <cstdio>
#include <inttypes.h>

#include <thread>
#include <semaphore>

#define PREFETCH( location ) _mm_prefetch( location, _MM_HINT_T0 )

constexpr size_t KiB = 1024;
constexpr size_t MiB = 1024 * KiB;
constexpr size_t GiB = 1024 * MiB;
constexpr size_t TiB = 1024 * GiB;

constexpr size_t operator "" _KiB( size_t val ) { return val * KiB; }
constexpr size_t operator "" _MiB( size_t val ) { return val * MiB; }
constexpr size_t operator "" _GiB( size_t val ) { return val * GiB; }
constexpr size_t operator "" _TiB( size_t val ) { return val * TiB; }

constexpr size_t VARIABLE_LENGTH_ARRAY = 1;

// Starting with 64-bit Windows 8.1/Windows Server 2012 R2. Not sure where the 128KiB comes from.
constexpr size_t WINDOWS_REQUIRED_MAX_ADDRESS_SPACE = 128_TiB - 128_KiB; 

// In order to memory map both source and destination files, the source file must be less than or equal to half the 
// maximum address space.
constexpr size_t MAX_COPYABLE_FILE_SIZE = WINDOWS_REQUIRED_MAX_ADDRESS_SPACE / 2;

// Limit how large the block hash metadata file can be. This excludes the header size so actual max size will
// be FILE_BLOCK_HASH_MAX_SIZE + sizeof(FileBlockHashHeader_s) - sizeof(Hash).
constexpr size_t FILE_BLOCK_HASH_MAX_SIZE = 16_MiB;
static_assert(FILE_BLOCK_HASH_MAX_SIZE < 2_GiB, "FILE_BLOCK_HASH_MAX_SIZE must be less than 2GiB due to synchronous ReadFile constraints.");

// Determine how many hashes can be supported by the target metadata file size.
typedef uint32_t Hash;
constexpr size_t FILE_BLOCK_HASH_MAX_HASH_COUNT = FILE_BLOCK_HASH_MAX_SIZE / sizeof( Hash );

// Determine the block sizes to be hashed based on max copyable file size, ceiled to the nearest 4KiB.
constexpr int64_t FILE_BLOCK_SIZE = ((MAX_COPYABLE_FILE_SIZE / FILE_BLOCK_HASH_MAX_HASH_COUNT + 4_KiB - 1) / 4_KiB) * 4_KiB;

constexpr wchar_t FILE_BLOCK_HASH_FILE_EXT[] = L".fbh";

// For the purposes of IO queuing, a large of number of threads is not necessary because few devices can sustain QD in the hundreds
// so multiple threads are likely to be I/O starved.
constexpr size_t IO_THREAD_MAX_COUNT = 8;

// Number of blocks processed by each IO thread.
constexpr size_t BLOCKS_PER_IO_THREAD = 8;

// How big to make a file map so the system doesn't use up crazy amounts of memory. This can still be quite big.
constexpr size_t FILE_MAP_VIEW_SIZE = IO_THREAD_MAX_COUNT * BLOCKS_PER_IO_THREAD * FILE_BLOCK_SIZE;
static_assert(FILE_MAP_VIEW_SIZE < 2_GiB, "File map view size must be less than 2GB due to Win32 API constraints.");

constexpr char HELP_TEXT[] = R"(
==============================================================================
deltacopy usage:
    deltacopy src=<path> dst=<path>

src and dst argument order does not matter. Paths can be relative or absolute.
Copying directories is currently unsupported.
)";

enum FileBlockHashHeaderVersion_e
{
	FBH_HEADER_INITIAL_VERSION,
	FBH_HEADER_VERSION_COUNT,
	FBH_HEADER_CURRENT_VERSION = FBH_HEADER_INITIAL_VERSION,
};

struct FileBlockHashHeader_s
{
	uint32_t headerVersion;
	
	uint64_t srcFileTimestamp;

	uint64_t blockCount;
	uint32_t blockHashes[VARIABLE_LENGTH_ARRAY];
};

static struct
{
	SYSTEM_INFO sysInfo;
	HANDLE processHeap = INVALID_HANDLE_VALUE;

	const wchar_t* srcFilePathArg = nullptr;
	const wchar_t* dstFilePathArg = nullptr;

	wchar_t srcFilePathAbsolute[MAX_PATH];
	wchar_t dstFilePathAbsolute[MAX_PATH];
	wchar_t* srcFilename;
	wchar_t* dstFilename;

	HANDLE srcFileHnd = INVALID_HANDLE_VALUE;
	HANDLE srcFileMappingHnd = INVALID_HANDLE_VALUE;
	HANDLE dstFileHnd = INVALID_HANDLE_VALUE;
	HANDLE dstFileMappingHnd = INVALID_HANDLE_VALUE;

	uint8_t* srcFileBytes;
	uint8_t* dstFileBytes;

	wchar_t dstFileBlockHashFilePath[MAX_PATH];
	FileBlockHashHeader_s* dstFileBlockHashData;
	HANDLE dstFileBlockHashHnd;

	uint8_t* dstFileBytesToFlush = nullptr;
	size_t dstFileBytesFlushSize = 0;
	std::binary_semaphore flushRequested = std::binary_semaphore{ 0 };
	std::binary_semaphore flushDone = std::binary_semaphore{ 0 };
	bool flushThreadNeeded = false;

	size_t totalBytesWritten = 0;
} s_state;

static struct
{
	std::counting_semaphore< IO_THREAD_MAX_COUNT > pendingIOWork{ 0 };
	std::binary_semaphore pendingIOWorkComplete{ 0 };
	size_t threadCount = 0;

	uint64_t blockCount;

	uint64_t baseBlockIdx;
} s_sharedIOThreadState;

// ================================== CRC-32 from Stephan Baume ==================================
// Modified to be simpler to integrate in this code.
constexpr uint32_t CRC32Polynomial = 0xEDB88320;
uint32_t Crc32Lookup[16][256];
void crc32_precompute_lookup_table()
{
	// my improvement of Wolf's code
	// approx. 0.18 nanoseconds on my PC / GCC9-x64
	Crc32Lookup[0][0] = 0;
	// compute each power of two (all numbers with exactly one bit set)
	uint32_t crc = Crc32Lookup[0][0x80] = CRC32Polynomial;
	for ( uint32_t next = 0x40; next != 0; next >>= 1 )
	{
		crc = (crc >> 1) ^ ((crc & 1) * CRC32Polynomial);
		Crc32Lookup[0][next] = crc;
	}
	// the main idea is:
	// table[a ^ b] = table[a] ^ table[b];
	// therefore if we know all values up to a power of two called x
	// we can compute table[x + y] where x > y:
	// table[x + y] = table[x ^ y] = table[x] ^ table[y]
	// example:
	// the previous loop computed table[1] and table[2],
	// so that x = 2 (a power of two) and y = 1 (fulfilling x > y)
	// now x + y = x ^ y = 2 + 1 = 2 ^ 1
	// and table[x + y] = table[x ^ y] = table[x] ^ table[y]
	// which means table[3] = table[2] ^ table[1]
	// compute all values between two powers of two
	// i.e. 3, 5,6,7, 9,10,11,12,13,14,15, 17,...
	for ( uint32_t powerOfTwo = 2; powerOfTwo <= 0x80; powerOfTwo <<= 1 )
	{
		uint32_t crcExtraBit = Crc32Lookup[0][powerOfTwo];
		for ( uint32_t i = 1; i < powerOfTwo; i++ )
			Crc32Lookup[0][i + powerOfTwo] = Crc32Lookup[0][i] ^ crcExtraBit;
	}

	for ( int slice = 1; slice < 16; slice++ )
	{
		for ( uint32_t i = 0; i < 256; ++i )
			Crc32Lookup[slice][i] = (Crc32Lookup[slice - 1][i] >> 8) ^ Crc32Lookup[0][Crc32Lookup[slice - 1][i] & 0xFF];
	}
		 
}

/// compute CRC32 (Slicing-by-16 algorithm, prefetch upcoming data blocks)
uint32_t crc32_16bytes_prefetch( const void* data, size_t length, uint32_t previousCrc32, size_t prefetchAhead )
{
	// CRC code is identical to crc32_16bytes (including unrolling), only added prefetching
	// 256 bytes look-ahead seems to be the sweet spot on Core i7 CPUs

	uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
	const uint32_t* current = (const uint32_t*)data;

	// enabling optimization (at least -O2) automatically unrolls the for-loop
	const size_t Unroll = 4;
	const size_t BytesAtOnce = 16 * Unroll;

	while ( length >= BytesAtOnce + prefetchAhead )
	{
		PREFETCH( ((const char*)current) + prefetchAhead );

		for ( size_t unrolling = 0; unrolling < Unroll; unrolling++ )
		{
			uint32_t one = *current++ ^ crc;
			uint32_t two = *current++;
			uint32_t three = *current++;
			uint32_t four = *current++;
			crc = Crc32Lookup[0][(four >> 24) & 0xFF] ^
				Crc32Lookup[1][(four >> 16) & 0xFF] ^
				Crc32Lookup[2][(four >> 8) & 0xFF] ^
				Crc32Lookup[3][four & 0xFF] ^
				Crc32Lookup[4][(three >> 24) & 0xFF] ^
				Crc32Lookup[5][(three >> 16) & 0xFF] ^
				Crc32Lookup[6][(three >> 8) & 0xFF] ^
				Crc32Lookup[7][three & 0xFF] ^
				Crc32Lookup[8][(two >> 24) & 0xFF] ^
				Crc32Lookup[9][(two >> 16) & 0xFF] ^
				Crc32Lookup[10][(two >> 8) & 0xFF] ^
				Crc32Lookup[11][two & 0xFF] ^
				Crc32Lookup[12][(one >> 24) & 0xFF] ^
				Crc32Lookup[13][(one >> 16) & 0xFF] ^
				Crc32Lookup[14][(one >> 8) & 0xFF] ^
				Crc32Lookup[15][one & 0xFF];
		}

		length -= BytesAtOnce;
	}

	const uint8_t* currentChar = (const uint8_t*)current;
	// remaining 1 to 63 bytes (standard algorithm)
	while ( length-- != 0 )
		crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

	return ~crc; // same as crc ^ 0xFFFFFFFF
}
// ================================== CRC-32 from Stephan Baume ==================================

const char* PrettyFormatSize( uint64_t size, double* outPrettySize )
{
	const char* prettySizeSuffix = "KiB";
	*outPrettySize = static_cast< double >(size) / static_cast< double >(KiB);
	if ( size > TiB )
	{
		*outPrettySize = static_cast< double >(size) / static_cast< double >(TiB);
		prettySizeSuffix = "TiB";
	}
	else if ( size > GiB )
	{
		*outPrettySize = static_cast< double >(size) / static_cast< double >(GiB);
		prettySizeSuffix = "GiB";
	}
	else if ( size > MiB )
	{
		*outPrettySize = static_cast< double >(size) / static_cast< double >(MiB);
		prettySizeSuffix = "MiB";
	}

	return prettySizeSuffix;
}

void PrintLastWin32Error()
{
	wchar_t errorMessage[512];
	const DWORD lastError = GetLastError();
	FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM, nullptr, lastError, 0, errorMessage, ARRAYSIZE( errorMessage ), nullptr );
	printf( "ERROR: %ls", errorMessage );
}

void FlushFileThread()
{
	for ( ;; )
	{
		s_state.flushRequested.acquire();

		if ( !s_state.flushThreadNeeded )
			return;

		FlushViewOfFile( s_state.dstFileBytesToFlush, s_state.dstFileBytesFlushSize );
		UnmapViewOfFile( s_state.dstFileBytesToFlush );
		s_state.dstFileBytesFlushSize = 0;
		s_state.dstFileBytesToFlush = nullptr;

		s_state.flushDone.release();
	}
}

void BlockCopyThread(uint64_t threadIdx)
{
	for ( ;; )
	{
		s_sharedIOThreadState.pendingIOWork.acquire();

		if ( s_sharedIOThreadState.threadCount == 0 )
			break;

		const size_t blocksPerThread = s_sharedIOThreadState.blockCount / s_sharedIOThreadState.threadCount;
		const size_t blockStartIdx = blocksPerThread * threadIdx;
		const size_t blockEndIdx = (threadIdx == s_sharedIOThreadState.threadCount - 1) ? s_sharedIOThreadState.blockCount : blockStartIdx + blocksPerThread;
		for ( size_t currBlockIdx = blockStartIdx; currBlockIdx < blockEndIdx; ++currBlockIdx )
		{
			const size_t actualBlockIdx = s_sharedIOThreadState.baseBlockIdx + currBlockIdx;
			const uint32_t crc32 = crc32_16bytes_prefetch( s_state.srcFileBytes + FILE_BLOCK_SIZE * currBlockIdx, FILE_BLOCK_SIZE, 0, 256 );
			if ( actualBlockIdx >= s_state.dstFileBlockHashData->blockCount || crc32 != s_state.dstFileBlockHashData->blockHashes[actualBlockIdx] )
			{
				printf( "Block %llu differs, copying...\n", actualBlockIdx );
				memcpy( s_state.dstFileBytes + FILE_BLOCK_SIZE * currBlockIdx, s_state.srcFileBytes + FILE_BLOCK_SIZE * currBlockIdx, FILE_BLOCK_SIZE );
				s_state.totalBytesWritten += FILE_BLOCK_SIZE;
			}
			else
			{
				printf( "Block %llu has no changes, skipping.\n", actualBlockIdx );
			}
			s_state.dstFileBlockHashData->blockHashes[actualBlockIdx] = crc32;
		}

		if ( threadIdx == s_sharedIOThreadState.threadCount - 1 )
			s_sharedIOThreadState.pendingIOWorkComplete.release();
	}
}

inline void DeltaCopyFileView( uint64_t offset, uint64_t viewSize )
{
	s_state.srcFileBytes = static_cast< uint8_t* >(MapViewOfFile( s_state.srcFileMappingHnd, FILE_MAP_READ, offset >> 32, offset & UINT32_MAX, viewSize ));
	s_state.dstFileBytes = static_cast< uint8_t* >(MapViewOfFile( s_state.dstFileMappingHnd, FILE_MAP_WRITE, offset >> 32, offset & UINT32_MAX, viewSize ));

	const size_t blockCount = viewSize / FILE_BLOCK_SIZE;
	//for ( size_t blockIdx = 0; blockIdx < blockCount; ++blockIdx )
	//{
	//	const size_t actualBlockIdx = offset / FILE_BLOCK_SIZE + blockIdx;
	//	const uint32_t crc32 = crc32_16bytes_prefetch( s_state.srcFileBytes + FILE_BLOCK_SIZE * blockIdx, FILE_BLOCK_SIZE, 0, 256 );
	//	if ( actualBlockIdx >= s_state.dstFileBlockHashData->blockCount || crc32 != s_state.dstFileBlockHashData->blockHashes[actualBlockIdx] )
	//	{
	//		printf( "Block %llu differs, copying...", actualBlockIdx );
	//		memcpy( s_state.dstFileBytes + FILE_BLOCK_SIZE * blockIdx, s_state.srcFileBytes + FILE_BLOCK_SIZE * blockIdx, FILE_BLOCK_SIZE );
	//		s_state.totalBytesWritten += FILE_BLOCK_SIZE;
	//		printf( "done\n" );
	//	}
	//	else
	//	{
	//		printf( "Block %llu has no changes, skipping.\n", actualBlockIdx );
	//	}
	//	s_state.dstFileBlockHashData->blockHashes[actualBlockIdx] = crc32;
	//}

	s_sharedIOThreadState.baseBlockIdx = offset / FILE_BLOCK_SIZE;
	s_sharedIOThreadState.blockCount = blockCount;
	s_sharedIOThreadState.pendingIOWork.release( s_sharedIOThreadState.threadCount );
	s_sharedIOThreadState.pendingIOWorkComplete.acquire();

	if ( blockCount * FILE_BLOCK_SIZE < viewSize )
	{
		const size_t blockIdx = blockCount;
		const size_t actualBlockIdx = offset / FILE_BLOCK_SIZE + blockIdx;

		const size_t lastBlockSize = viewSize - FILE_BLOCK_SIZE * blockIdx;
		const uint32_t crc32 = crc32_16bytes_prefetch( s_state.srcFileBytes + FILE_BLOCK_SIZE * blockIdx, lastBlockSize, 0, 256 );
		if ( actualBlockIdx >= s_state.dstFileBlockHashData->blockCount || crc32 != s_state.dstFileBlockHashData->blockHashes[actualBlockIdx] )
		{
			printf( "Block %llu differs, copying...", actualBlockIdx );
			memcpy( s_state.dstFileBytes + FILE_BLOCK_SIZE * blockIdx, s_state.srcFileBytes + FILE_BLOCK_SIZE * blockIdx, lastBlockSize );
			s_state.totalBytesWritten += lastBlockSize;
			printf( "done\n" );
		}
		else
		{
			printf( "Block %llu has no changes, skipping.\n", actualBlockIdx );
		}

		s_state.dstFileBlockHashData->blockHashes[actualBlockIdx] = crc32;
	}

	if ( s_state.dstFileBytesToFlush != nullptr )
	{
		printf( "%s", "Flushing writes to destination so system does not use too much memory.\n" );
		s_state.flushDone.acquire();
	}

	s_state.dstFileBytesToFlush = s_state.dstFileBytes;
	s_state.dstFileBytesFlushSize = viewSize;

	UnmapViewOfFile( s_state.srcFileBytes );
	s_state.srcFileBytes = nullptr;
	s_state.dstFileBytes = nullptr;

	s_state.flushRequested.release();
}

int DeltaCopy()
{
	const BOOL srcIsNetworkPath = PathIsNetworkPath( s_state.srcFilePathAbsolute );
	const BOOL dstIsNetworkPath = PathIsNetworkPath( s_state.dstFilePathAbsolute );

	// Assume that most machines in the wild have at least 2 cores in 2022. However, if either the source or destination files are network resources,
	// force single threaded mode because network I/O does not work well with high QD/random access the way multiple threads would create.
	const size_t ioThreadCount = (srcIsNetworkPath || dstIsNetworkPath) ? 1 : max( 1, min( s_state.sysInfo.dwNumberOfProcessors / 4, IO_THREAD_MAX_COUNT ) );

	s_state.srcFileHnd = CreateFile( s_state.srcFilePathAbsolute, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( s_state.srcFileHnd == INVALID_HANDLE_VALUE )
	{
		printf( "ERROR: Failed to open %ls\n", s_state.srcFilePathAbsolute );
		PrintLastWin32Error();;
		return 1;
	}

	s_state.dstFileHnd = CreateFile( s_state.dstFilePathAbsolute, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( s_state.dstFileHnd == INVALID_HANDLE_VALUE )
	{
		printf( "ERROR: Failed to open %ls\n", s_state.dstFilePathAbsolute );
		PrintLastWin32Error();
		return 1;
	}

	LARGE_INTEGER srcFileSize;
	GetFileSizeEx( s_state.srcFileHnd, &srcFileSize );

	LARGE_INTEGER dstFileSize;
	GetFileSizeEx( s_state.dstFileHnd, &dstFileSize );

	// If the source file is smaller than a block, just copy the source file to destination.
	if ( srcFileSize.QuadPart < FILE_BLOCK_SIZE )
	{
		CloseHandle( s_state.dstFileHnd );
		s_state.dstFileHnd = INVALID_HANDLE_VALUE;

		CopyFile( s_state.srcFilePathAbsolute, s_state.dstFilePathAbsolute, FALSE );
		return 0;
	}

	const size_t blockCount = static_cast< size_t >(srcFileSize.QuadPart / FILE_BLOCK_SIZE + 1);
	const uint32_t fileBlockHashFileSize = static_cast< int32_t >( sizeof( FileBlockHashHeader_s ) + (blockCount - 1) * sizeof( Hash ) ); // Header already includes space for a single block hash.
	s_state.dstFileBlockHashData = static_cast< FileBlockHashHeader_s* >( HeapAlloc( s_state.processHeap, HEAP_ZERO_MEMORY, fileBlockHashFileSize ) );

	s_state.dstFileBlockHashHnd = CreateFile( s_state.dstFileBlockHashFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );

	// Only reading in fileBlockHashFileSize automatically handles the source file being smaller than the destination file by truncating the hashes for removed blocks.
	DWORD bytesRead;
	const BOOL readFBH = ReadFile( s_state.dstFileBlockHashHnd, s_state.dstFileBlockHashData, fileBlockHashFileSize, &bytesRead, nullptr );
	if ( readFBH == FALSE )
	{
		PrintLastWin32Error();
		return 1;
	}

	FILETIME srcFileTime;
	GetFileTime( s_state.srcFileHnd, nullptr, nullptr, &srcFileTime );

	uint64_t srcFileTimestamp = (static_cast< uint64_t >( srcFileTime.dwHighDateTime ) << 32u) | srcFileTime.dwLowDateTime;
	if ( s_state.dstFileBlockHashData->srcFileTimestamp == srcFileTimestamp )
	{
		printf( "%s", "Source file has not changed since last copy, nothing to do!\n" );
		return 0;
	}

	// Truncate destination file before mapping it if the source file has shrunk since the last copy.
	if ( dstFileSize.QuadPart > srcFileSize.QuadPart )
	{
		SetFilePointerEx( s_state.dstFileHnd, srcFileSize, nullptr, FILE_BEGIN );
		SetEndOfFile( s_state.dstFileHnd );
		SetFileValidData( s_state.dstFileHnd, srcFileSize.QuadPart );
		SetFilePointerEx( s_state.dstFileHnd, { 0, 0 }, nullptr, FILE_BEGIN );
	}

	// Map source and destination files into memory.
	s_state.srcFileMappingHnd = CreateFileMapping( s_state.srcFileHnd, nullptr, PAGE_READONLY, 0, 0, nullptr );
	s_state.dstFileMappingHnd = CreateFileMapping( s_state.dstFileHnd, nullptr, PAGE_READWRITE, srcFileSize.HighPart, srcFileSize.LowPart, nullptr );

	//MEMORY_BASIC_INFORMATION mappedSrcInfo;
	//VirtualQuery( s_state.srcFileBytes, &mappedSrcInfo, sizeof( mappedSrcInfo ) );

	//MEMORY_BASIC_INFORMATION mappedDstInfo;
	//VirtualQuery( s_state.dstFileBytes, &mappedDstInfo, sizeof( mappedDstInfo ) );

	crc32_precompute_lookup_table();

	s_state.flushThreadNeeded = true;
	std::thread flushThread( FlushFileThread );

	std::thread ioThreads[IO_THREAD_MAX_COUNT];
	s_sharedIOThreadState.threadCount = ioThreadCount;
	for ( uint64_t threadIdx = 0; threadIdx < ioThreadCount; ++threadIdx )
		ioThreads[threadIdx] = std::thread( BlockCopyThread, threadIdx );

	const size_t viewCount = srcFileSize.QuadPart / FILE_MAP_VIEW_SIZE;
	for ( size_t viewIdx = 0; viewIdx < viewCount; ++viewIdx )
	{
		DeltaCopyFileView( viewIdx * FILE_MAP_VIEW_SIZE, FILE_MAP_VIEW_SIZE );
		//printf( "Processed %.2lf%% of file\n", static_cast< double >(viewIdx * FILE_MAP_VIEW_SIZE) / static_cast< double >(srcFileSize.QuadPart) );
	}
	
	const size_t lastViewSize = srcFileSize.QuadPart - viewCount * FILE_MAP_VIEW_SIZE;
	if ( viewCount * FILE_MAP_VIEW_SIZE < static_cast< size_t >( srcFileSize.QuadPart ) )
		DeltaCopyFileView( viewCount * FILE_MAP_VIEW_SIZE, lastViewSize );

	s_state.flushDone.acquire();
	s_state.flushThreadNeeded = false;
	s_state.flushRequested.release();
	flushThread.join();

	s_sharedIOThreadState.threadCount = 0;
	s_sharedIOThreadState.pendingIOWork.release( ioThreadCount );
	for ( size_t threadIdx = 0; threadIdx < ioThreadCount; ++threadIdx )
		ioThreads[threadIdx].join();

	SYSTEMTIME systemTime;
	GetSystemTime( &systemTime );

	FILETIME currentTime;
	SystemTimeToFileTime( &systemTime, &currentTime );
	SetFileTime( s_state.dstFileHnd, nullptr, nullptr, &currentTime );

	double prettyBytesWritten;
	const char* prettyBytesWrittenSuffix = PrettyFormatSize( s_state.totalBytesWritten, &prettyBytesWritten );

	double prettyFileSize;
	const char* prettyFileSizeSuffix = PrettyFormatSize( srcFileSize.QuadPart, &prettyFileSize );

	double writtenPercent = static_cast< double >(s_state.totalBytesWritten) / static_cast< double >(srcFileSize.QuadPart) * 100.0;
	printf( "Finished! Wrote %.2lf%s out of %.2lf%s which was %.2lf%% of original file size\n", prettyBytesWritten, prettyBytesWrittenSuffix, prettyFileSize, prettyFileSizeSuffix, writtenPercent );

	s_state.dstFileBlockHashData->headerVersion = FBH_HEADER_CURRENT_VERSION;
	s_state.dstFileBlockHashData->blockCount = blockCount;
	s_state.dstFileBlockHashData->srcFileTimestamp = srcFileTimestamp;

	SetFilePointerEx( s_state.dstFileBlockHashHnd, { fileBlockHashFileSize, 0 }, nullptr, FILE_BEGIN );
	SetEndOfFile( s_state.dstFileBlockHashHnd );
	SetFileValidData( s_state.dstFileBlockHashHnd, fileBlockHashFileSize );
	SetFilePointerEx( s_state.dstFileBlockHashHnd, { 0, 0 }, nullptr, FILE_BEGIN );

	DWORD bytesWritten;
	WriteFile( s_state.dstFileBlockHashHnd, s_state.dstFileBlockHashData, fileBlockHashFileSize, &bytesWritten, nullptr );
	if ( bytesWritten == 0 )
	{
		PrintLastWin32Error();
		return 1;
	}
	FlushFileBuffers( s_state.dstFileBlockHashHnd );

	printf( "Updated file block hash metadata\n" );

	return 0;
}

void Cleanup()
{
	if ( s_state.srcFileBytes != nullptr )
		UnmapViewOfFile( s_state.srcFileBytes );

	if ( s_state.srcFileMappingHnd != INVALID_HANDLE_VALUE )
		CloseHandle( s_state.srcFileMappingHnd );

	if ( s_state.srcFileHnd != INVALID_HANDLE_VALUE )
		CloseHandle( s_state.srcFileHnd );

	if ( s_state.dstFileBytes != nullptr )
		UnmapViewOfFile( s_state.dstFileBytes );

	if ( s_state.dstFileMappingHnd != INVALID_HANDLE_VALUE )
		CloseHandle( s_state.dstFileMappingHnd );

	if ( s_state.dstFileHnd != INVALID_HANDLE_VALUE )
		CloseHandle( s_state.dstFileHnd );

	if ( s_state.dstFileBlockHashHnd != INVALID_HANDLE_VALUE )
		CloseHandle( s_state.dstFileBlockHashHnd );

	if ( s_state.dstFileBlockHashData != nullptr )
		HeapFree( s_state.processHeap, 0, s_state.dstFileBlockHashData );
}

int wmain(int argc, wchar_t* argv[])
{
	int returnCode = 0;

	GetSystemInfo( &s_state.sysInfo );
	// + 1 because addresses are inclusive and we want the size of the address space.
	const uintptr_t maxAddressSpace = reinterpret_cast< uintptr_t >(s_state.sysInfo.lpMaximumApplicationAddress) - reinterpret_cast< uintptr_t >(s_state.sysInfo.lpMinimumApplicationAddress) + 1;
	if ( maxAddressSpace < WINDOWS_REQUIRED_MAX_ADDRESS_SPACE )
	{
		printf( R"(Current version of Windows does not support the required address space of 128TiB. See https://learn.microsoft.com/en-us/windows/win32/memory/memory-limits-for-windows-releases#memory-and-address-space-limits)" );
		return 1;
	}

	s_state.processHeap = GetProcessHeap();

	if ( argc != 3 )
	{
		printf( "%s", "ERROR: Insufficient or unexpected arguments!\n" );
		printf( "%s", HELP_TEXT );
		returnCode = 1;
		goto exit;
	}

	for ( int i = 1; i < 3; ++i )
	{
		if ( wcsstr( argv[i], L"src=" ) )
			s_state.srcFilePathArg = argv[i] + 4;
		else if ( wcsstr( argv[i], L"dst=" ) )
			s_state.dstFilePathArg = argv[i] + 4;
	}

	if ( s_state.srcFilePathArg == nullptr )
	{
		printf( "%s", "ERROR: Missing source file path.\n" );
		printf( "%s", HELP_TEXT );
		returnCode = 1;
		goto exit;
	}
	printf( "Source file path argument: \t\t%ls\n", s_state.srcFilePathArg );

	if ( s_state.dstFilePathArg == nullptr )
	{
		printf( "%s", "ERROR: Missing destination file path.\n" );
		printf( "%s", HELP_TEXT );
		returnCode = 1;
		goto exit;
	}
	printf( "Destination file path argument: \t%ls\n", s_state.dstFilePathArg );

	printf( "\n" );

	// For logging information
	{
		wchar_t currentDir[MAX_PATH];
		GetCurrentDirectory( ARRAYSIZE( currentDir ), currentDir );
		printf( "Current working directory: \t\t%ls\n", currentDir );
	}

	GetFullPathName( s_state.srcFilePathArg, ARRAYSIZE( s_state.srcFilePathAbsolute ), s_state.srcFilePathAbsolute, &s_state.srcFilename );
	GetFullPathName( s_state.dstFilePathArg, ARRAYSIZE( s_state.dstFilePathAbsolute ), s_state.dstFilePathAbsolute, &s_state.dstFilename );
	
	if ( s_state.srcFilename == nullptr || s_state.dstFilename == nullptr )
	{
		printf( "%s", "ERROR: Copying directories is currently unsupported." );
		printf( "%s", HELP_TEXT );
		returnCode = 1;
		goto exit;
	}

	wcscpy_s( s_state.dstFileBlockHashFilePath, s_state.dstFilePathAbsolute );
	for ( size_t i = wcslen( s_state.dstFileBlockHashFilePath ); i > 0; )
	{
		--i;
		if ( s_state.dstFileBlockHashFilePath[i] == L'.' )
		{
			wcscpy_s( s_state.dstFileBlockHashFilePath + i, 5, FILE_BLOCK_HASH_FILE_EXT );
			break;
		}
	}

	printf( "Resolved source path: \t\t\t%ls\n", s_state.srcFilePathAbsolute );
	printf( "Resolved destination path: \t\t%ls\n", s_state.dstFilePathAbsolute );
	printf( "Destination file block hash path: \t%ls\n", s_state.dstFileBlockHashFilePath );

	printf( "\n" );
	
	returnCode = DeltaCopy();

exit:
	Cleanup();
	return returnCode;
}