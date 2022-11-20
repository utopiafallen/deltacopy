#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#include <Windows.h>

#include <cstdio>

constexpr char HELP_TEXT[] = R"(
deltacopy usage:
    deltacopy src=<path> dst=<path>

src and dst argument order does not matter. Paths can be relative or absolute.
)";

int main( int argc, const char* argv[] )
{
	const char* srcPathArg = nullptr;
	const char* dstPathArg = nullptr;

	if ( argc != 3 )
	{
		printf( "%s", "ERROR: Insufficient or unexpected arguments!\n" );
		goto error_exit;
	}

	for ( int i = 1; i < 3; ++i )
	{
		if ( strstr( argv[i], "src=" ) )
			srcPathArg = argv[i] + 4;
		else if ( strstr( argv[i], "dst=" ) )
			dstPathArg = argv[i] + 4;
	}

	if ( srcPathArg == nullptr )
	{
		printf( "%s", "ERROR: Missing source file path.\n" );
		goto error_exit;
	}
	printf( "Source file path argument: %s\n", srcPathArg );

	if ( dstPathArg == nullptr )
	{
		printf( "%s", "ERROR: Missing destination file path.\n" );
		goto error_exit;
	}
	printf( "Destination file path argument: %s\n", dstPathArg );

	char currentDir[MAX_PATH];
	GetCurrentDirectoryA( sizeof( currentDir ), currentDir );
	printf( "Current working directory: %s", currentDir );

	return 0;

error_exit:
	printf( "%s", HELP_TEXT );
	return 1;
}