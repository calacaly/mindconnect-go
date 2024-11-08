#!/bin/bash

APISEPC_PATH=./api-spec
APIGEN_PATH=./internal/api
TOOL=swagger

install() {
    if ! command -v ${TOOL} ;then
        echo "Installing ${TOOL}"
        go install github.com/go-swagger/go-swagger/cmd/swagger@latest
    fi
}

gen_apis() {
    for file in $(ls ${APISEPC_PATH} | grep yaml); do
        echo "Generating models for ${file}"
        package=$(echo "${file}" | cut -d '-' -f 1)
        version=$(echo "${file}" | cut -d '-' -f 2)
        if [[ ! -d ${APIGEN_PATH}/${package}/${version} ]];then 
            mkdir -p ${APIGEN_PATH}/${package}/${version}
        fi
        ${TOOL} generate client -f ${APISEPC_PATH}/${file} -t ${APIGEN_PATH}/${package}/${version}/ \
             --default-scheme=https
    done
}


install
gen_apis