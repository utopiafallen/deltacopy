# deltacopy
Fast block-based delta copies on Windows.

deltacopy will compute hashes for fixed size blocks and only copy blocks that are different or new. Hashes are saved next to destination copy to accelerate future copy operations.

Credit to Red Gavin for xxHash C++17 port. Single header libraries FTW!