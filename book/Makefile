.PHONY: all pdf clean watch

MAIN = main
TEX_FILES = $(shell find . -name '*.tex')
BIB_FILES = $(shell find . -name '*.bib')

all: pdf

pdf: $(MAIN).pdf

$(MAIN).pdf: $(TEX_FILES) $(BIB_FILES)
	@echo "==> Compiling LaTeX document ($(MAIN).tex)..."
	latexmk -pdf -interaction=nonstopmode -synctex=1 $(MAIN).tex || pdflatex -interaction=nonstopmode $(MAIN).tex
	@if [ -f $(MAIN).bcf ] || [ -f $(MAIN).aux ]; then \
		biber $(MAIN) 2>/dev/null || bibtex $(MAIN) 2>/dev/null || true; \
		pdflatex -interaction=nonstopmode $(MAIN).tex; \
		pdflatex -interaction=nonstopmode $(MAIN).tex; \
	fi
	@echo "==> Build complete: $(MAIN).pdf"

watch:
	latexmk -pdf -pvc -interaction=nonstopmode $(MAIN).tex

clean:
	latexmk -C
	rm -f *.aux *.bbl *.bcf *.blg *.fdb_latexmk *.fls *.log *.out *.run.xml *.synctex.gz *.toc *.lot *.lof *.idx *.ind *.ilg
	find . -name "*.aux" -delete
