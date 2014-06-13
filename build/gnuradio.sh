#GNU Radio 3.7.4 paths
#This assumes the default installation directory of /usr/local
#cmake and make were run with no optional parameters

export GNURADIO='/usr/local'
export LD_LIBRARY_PATH="$GNURADIO/lib64"
export PYTHONPATH="$GNURADIO/lib64/python2.6/site-packages"
export GRC_BLOCK_PATH="$GNURADIO/share/gnuradio/grc/blocks"
