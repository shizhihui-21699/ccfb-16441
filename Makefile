.PHONY: test bench demo scan lint

test:
	./vendor/bin/phpunit

# Lint every PHP file under the project's source and test trees.
lint:
	php -r '$$bad=0; foreach (["src","tests","examples","bin"] as $$d) { $$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($$d, FilesystemIterator::SKIP_DOTS)); foreach ($$it as $$f) { if ($$f->getExtension() === "php" && $$f->isFile()) { exec(escapeshellarg(PHP_BINARY)." -l ".escapeshellarg($$f->getPathname())." 2>&1", $$o, $$c); if ($$c) { fwrite(STDERR, implode("\n", $$o)); exit(1); } } } } echo "lint ok\n";'

bench:
	php -d opcache.enable_cli=1 -d opcache.jit=tracing -d opcache.jit_buffer_size=64M benchmarks/render_bench.php 100000

demo:
	php examples/demo.php

scan:
	php bin/tplguard-scan $${DIR:-data/skin} --policy=$${POLICY:-skin}
