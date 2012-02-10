all:
	(cd src; make)

clean:
	(cd src; make clean)

dialyzer:
	dialyzer --src -r src -I ebin
