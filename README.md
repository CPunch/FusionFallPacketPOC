This project was made after OpenFusion for the corresponding [blog on OpenPunk](https://openpunk.com/pages/fusionfall-openfusion/). This is just a base project to talk to/read packets from the FusionFall beta-20100104 client. This was made while writting the blog to cut all of the game server bloat and just provide a technical writeup for the packet structure. As this is just a technical write up this codebase is not designed to accept more than one connection at a time & is unsafe and will probably segfault. For a more complete example please reference src/CNProtocol.cpp & src/CNProtocol.hpp in the [OpenFusion repository](https://github.com/OpenFusionProject/OpenFusion/blob/master/src/CNProtocol.cpp).

# Compiling

```bash
clang++ src/main.cpp -o server
```