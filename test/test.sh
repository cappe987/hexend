#!/bin/bash

# tshark depends on the current user being in the 'wireshark' group, or getting
# the permissions in other ways.

hexend=$1
if [ "$#" -ge 2 ]; then
	test=$2
else
	test=""
fi

in=veth1
out=veth2
curr_test="none"
failed=0

ip link add dev $in type veth peer name $out
ip link set dev $in up
ip link set dev $out up


show() {
	echo "$curr_test: $@"
}

basic_count() {
	frame="ffffffffffffaaaaaaaaaaaa0000"
	src="aa:aa:aa:aa:aa:aa"
	dst="ff:ff:ff:ff:ff:ff"
	num_pkt=5

	tmp=$(mktemp)

	tshark -lni $out ether src $src and ether dst $dst 1> $tmp 2>/dev/null &
	PID=$!
	sleep 1

	echo "$frame" | $hexend $in -c $num_pkt -i 0 -q
	sleep 2
	kill $PID 2>/dev/null
	NUM=$(cat $tmp | grep "$src → $dst" | wc -l)

	if [ $NUM -ne $num_pkt ]; then
		show "Received $NUM/$num_pkt frames"
		return 1
	fi

	return 0
}

basic_interval() {
	# Test could be sensitive to timing. Maybe rewrite it
	frame="ffffffffffffaaaaaaaaaaaa0000"
	src="aa:aa:aa:aa:aa:aa"
	dst="ff:ff:ff:ff:ff:ff"
	num_pkt=5
	interval=1

	tmp=$(mktemp)

	tshark -lni $out ether src $src and ether dst $dst 1> $tmp 2>/dev/null &
	PID=$!
	sleep 1

	echo "$frame" | $hexend $in -c $num_pkt -i $interval -q &
	sleep 1
	for i in $(seq 1 5); do
		NUM=$(cat $tmp | grep "$src → $dst" | wc -l)
		if [ "$i" -ne "$NUM" ]; then
			show "$NUM frames received after $i second(s)"
			return 1
		fi
		sleep 1
	done
	kill $PID 2>/dev/null

	return 0
}

basic_verbose() {
	frame="ffffffffffffaaaaaaaaaaaa0000"

	OUT=$(echo "$frame" | $hexend lo -c 1 -v | tail -1)

	if ! echo "$OUT" | grep -q "ffff ffff ffff aaaa aaaa aaaa 0000$"; then
		show "Verbose format incorrect"
		show "$OUT"
		return 1
	fi

	return 0
}

zero_interval() {
	frame="ffffffffffffaaaaaaaaaaaa0000"
	src="aa:aa:aa:aa:aa:aa"
	dst="ff:ff:ff:ff:ff:ff"
	count=20000
	# On my computer, zero interval will put out ~250K frames in one
	# second, while the minimal float it can handle only reaches about 5K
	# frames before it rounds down to zero and becomes a zero-interval.

	tmp=$(mktemp)

	tshark -lni $out ether src $src and ether dst $dst 1> $tmp 2>/dev/null &
	PID=$!
	sleep 1

	echo "$frame" | $hexend $in -c $count -i 0 -q &
	PID2=$!
	sleep 1
	kill $PID2 2>/dev/null
	kill $PID 2>/dev/null
	received=$(wc -l < $tmp)
	if [ $received -ne $count ]; then
		show "Received $received/$count"
		return 1
	fi

	return 0
}

tests="basic_count basic_interval basic_verbose zero_interval"

if [ "$test" = "" ]; then
	echo "[TEST] Running tests"
	for t in $tests; do
		curr_test=$t
		if $t; then
			echo -e "[\e[32mPASS\e[0m] $t"
		else
			echo -e "[\e[31mFAIL\e[0m] $t"
			failed=1
		fi
	done
elif echo "$tests" | grep -q "$test"; then
	echo "[TEST] Running test: $test"
	curr_test=$test
	if $test; then
		echo -e "[\e[32mPASS\e[0m] $t"
	else
		echo -e "[\e[31mFAIL\e[0m] $t"
		failed=1
	fi
else
	echo "Test does not exist..."
	exit 1
fi

exit $failed
