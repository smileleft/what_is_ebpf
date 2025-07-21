#!/bin/bash
ip link set dev eth0 up
ethtool -K eth0 tx off rx off sg off tso off gso off gro off lro off

