all: test

test:
	find . -name "test.rb" -exec ruby -I. {} \;

clean:
	find . -name "*.dat" -exec rm {} \;
	find . -name "*.bak" -exec rm {} \;
	find . -name "*.log" -exec rm {} \;
