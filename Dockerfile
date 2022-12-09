FROM python:3.9.15-slim AS build

RUN mkdir /build
COPY . /build
WORKDIR /build

RUN pip install -r requirements.txt

WORKDIR /build/app
RUN for file in $(find -maxdepth 1 -name '*.py' ! -name 'setup.py'); do mv ${file} "${file}x"; done && \
    python setup.py build_ext --inplace && \
    chmod +x gg && \
    mv gg /usr/local/bin/gg && \
    mv *.so /usr/local/lib/python3.9/site-packages && \
    rm -rf /build

###############################
FROM scratch

COPY --from=build / /
CMD gg

