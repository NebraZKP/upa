# All .md files and their corresponding .pdf files
MD_FILES:=$(filter-out README.md,$(wildcard *.md))
PDF_FILES:=$(MD_FILES:.md=.pdf)

# By default, make all .pdf files that are out-of-date
default: $(PDF_FILES)

# Rule to create .pdf files from .md files
%.pdf: %.md
	pandoc -f markdown -t pdf -o $@ $<
