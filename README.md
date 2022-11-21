# deltacopy
Fast block-based delta copies on Windows.

deltacopy will compute hashes for fixed size blocks and only copy blocks that are different or new. Hashes are saved next to destination copy to accelerate future copy operations.

Credit to Stephan Brumme for crc32 implementation.