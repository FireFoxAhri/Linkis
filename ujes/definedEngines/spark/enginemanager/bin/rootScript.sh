#!/bin/bash

user=$1
commands=$2
sudo su - $user -c "$commands"