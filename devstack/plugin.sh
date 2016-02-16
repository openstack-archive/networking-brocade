#!/usr/bin/env bash

DIR_BRCD=$DEST/networking-brocade

if is_service_enabled net-brcd; then

    if [[ "$1" == "source" ]]; then
        :
    fi

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        cd $DIR_BRCD
        echo "Installing networking-brocade"
        setup_develop $DIR_BRCD
    fi

    if [[ "$1" == "clean" ]]; then
        :
    fi
fi
