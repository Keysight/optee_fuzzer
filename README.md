
# OP-TEE Fuzzer

This repository contains the code for a fuzzing prototype for the OP-TEE system call interface using AFL. It works by having a proxy CA that works as target from the perspective of AFL and that invokes a proxy TA that performs arbitrary system calls defined through a custom function call definition format. An AFL post library is used to discard invalid input files without invoking the TEE (which is relatively slow).

The fuzzer and ideas behind it were presented at Nullcon 2019 and Linaro Connect SAN19.

Slides: https://static.linaro.org/connect/san19/presentations/san19-225.pdf
Video: https://www.youtube.com/watch?v=7bYAwaJ7WZw

The code in this repository is a unpolished prototype that is released "as-is" to demonstrate the concepts of fuzzing a Trusted Execution Environment.

## Build Instructions

Ensure you have a fully checked out OP-TEE build tree. Clone this repository as subdirectory of the build tree. Apply the patches to the OP-TEE build system, client library and OS itself. Then build OP-TEE using the instructions provided at https://optee.readthedocs.io/en/latest/building/gits/build.html. As last step build the fuzzer using "make fuzzer" in the OP-TEE build folder. Additionally, cross-compile AFL for ARM.

Note: the provided (raw) patches are for OP-TEE 3.3.0. Porting them to a different OP-TEE version requires most likely some changes.

## Usage Instructions

Boot the system normally (using QEMU or using real hardware) and make sure the TEE functions normally (i.e. tee-supplicant running etc.) Copy the proxy TA to the correct folder (normally /lib/optee_armtz) and start AFL:

`AFL_POST_LIBRARY=/path/to/fuzzer/afl_validate.so
afl-fuzz -i /path/to/fuzzer/seeds -t 300+ -o /tmp/state -M $1 -- /path/to/fuzzer/tee_invoke_svc`

## License, Copyright and more

Copyright 2019 Riscure B.V. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Riscure B.V. reserves the right to dual-license the code under a different license at any future moment. Therefore, patches or code contributions cannot be accepted without transferring the copyright to Riscure B.V.

