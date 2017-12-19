FROM ubuntu:bionic

RUN useradd -m retdec
WORKDIR /home/retdec
ENV HOME /home/retdec

RUN apt-get -y update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential git bc graphviz upx cmake python zlib1g-dev flex bison libtinfo-dev autoconf pkg-config m4 libtool wget

USER retdec
RUN git clone --recursive https://github.com/avast-tl/retdec && \
	cd retdec && \
	mkdir build && \
	cd build && \
	cmake .. -DCMAKE_INSTALL_PREFIX=/home/retdec/retdec-install && \
	make -j$(nproc) && \
	make install

ENV PATH /home/retdec/retdec-install/bin:$PATH

CMD ["/bin/bash"]
