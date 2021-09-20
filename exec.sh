BAR='####################'
src_size=20
for i in {1..20}; do
       python3 proxsig.py; 
       bar_size=$(( $i * 20 / $src_size ))
       echo -ne "\r${BAR:0:$bar_size}"
       sleep .1
done
echo
