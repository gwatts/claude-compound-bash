.PHONY: release test

# Usage: make release V=1.2.3
release:
ifndef V
	$(error V is not set. Usage: make release V=1.2.3)
endif
	@echo "Releasing v$(V)..."
	perl -pi -e 's/"version": "[^"]+"/"version": "$(V)"/' .claude-plugin/plugin.json
	perl -pi -e 's/^VERSION="[^"]+"/VERSION="$(V)"/' scripts/launcher.sh
	git add .claude-plugin/plugin.json scripts/launcher.sh
	git commit -m "release: v$(V)"
	git tag "v$(V)"
	@echo "Tagged v$(V). Push with: git push origin main v$(V)"

test:
	go test ./...
