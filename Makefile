.PHONY: help dev bench

help:
	@make -qpRr | egrep -e '^[a-z].*:$$' | sed -e 's~:~~g' | sort

dev:
	ERL_AFLAGS="-kernel shell_history enabled" iex --name node@127.0.0.1 --cookie cookie -S mix

bench:
	mix run bench/trustex_bench.exs

