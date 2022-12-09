FROM python:3.9.15-slim AS build

RUN mkdir /build
COPY . /build
WORKDIR /build

RUN apt update && \
    apt install -y gcc
RUN pip install -r requirements.txt

WORKDIR /build/app
RUN for file in $(find -maxdepth 1 -name '*.py' ! -name 'setup.py'); do mv ${file} "${file}x"; done && \
    python setup.py build_ext --inplace && \
    chmod +x gg && \
    mv gg /usr/local/bin/gg && \
    chmod +x gg_controller && \
    mv gg_controller /usr/local/bin/gg_controller && \
    mv *.so /usr/local/lib/python3.9/site-packages && \
    rm -rf /build

RUN apt purge -y gcc && \
    rm -rf /var/lib/apt/lists/* && \
    rm /usr/local/bin/kopf

###############################
FROM scratch

COPY --from=build / /
CMD gg

