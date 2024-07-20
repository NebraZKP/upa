# Specifications

## Requirements

The PDF files are built using pandoc and latex.  For example:
```console
$ brew install pandoc
$ brew install mactex-no-gui
```

## Build

Run `make` in this directory
```console
$ make
```

**When making changes, squash all PDF changes into a single commit, to reduce
unnecessary binary changes in the commit history.**
