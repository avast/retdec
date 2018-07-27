FROM ubuntu:bionic

RUN useradd -m retdec
WORKDIR /home/retdec
ENV HOME /home/retdec

RUN apt-get -y update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y   \
	build-essential                                     \
	cmake                                               \
	git                                                 \
	perl                                                \
	python3                                             \
	doxygen                                             \
	graphviz                                            \
	upx                                                 \
	flex                                                \
	bison                                               \
	zlib1g-dev                                          \
	libtinfo-dev                                        \
	autoconf                                            \
	automake                                            \
	pkg-config                                          \
	m4                                                  \
	libtool

USER retdec
RUN git clone https://github.com/avast-tl/retdec && \
	cd retdec && \
	mkdir build && \
	cd build && \
	cmake .. -DCMAKE_INSTALL_PREFIX=/home/retdec/retdec-install && \
	make -j$(nproc) && \
	make install

ENV PATH /home/retdec/retdec-install/bin:$PATH
