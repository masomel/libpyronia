export SYSLIB=/usr/lib
export SYSINC=/usr/include

# install dependencies for pyronia userspace API library
echo "================= Installing libpyronia dependencies ================="
./scripts/install_smv

cd ./src/

# compile pyronia userspace API library
echo "================= Compiling pyronia user space library ================="
cmake .
make clean
make

# Copy library and header files to local machine
echo "================= Copying pyronia header files to: $SYSINC ================="
sudo cp pyronia_lib.h /usr/include

echo "================= Copying pyronia library to system folder: $SYSLIB ================="
sudo cp libpyronia.so /usr/lib
sudo cp libpyronia.so /usr/lib/x86_64-linux-gnu/
sudo cp libpyronia.so /lib/x86_64-linux-gnu/

echo "================= Installation completed ==============================="
