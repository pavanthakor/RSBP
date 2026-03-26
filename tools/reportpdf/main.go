package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

var (
	headingRE = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
)

func main() {
	var inPath string
	var outPath string
	var title string
	var author string
	var institute string

	flag.StringVar(&inPath, "in", "", "input markdown path")
	flag.StringVar(&outPath, "out", "", "output pdf path")
	flag.StringVar(&title, "title", "B.Tech Project Report", "document title")
	flag.StringVar(&author, "author", "", "author/candidate name")
	flag.StringVar(&institute, "institute", "", "institute/university name")
	flag.Parse()

	if strings.TrimSpace(inPath) == "" {
		fmt.Fprintln(os.Stderr, "missing -in")
		os.Exit(2)
	}
	if strings.TrimSpace(outPath) == "" {
		base := strings.TrimSuffix(filepath.Base(inPath), filepath.Ext(inPath))
		outPath = filepath.Join(filepath.Dir(inPath), base+".pdf")
	}

	f, err := os.Open(inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 18, 20)
	pdf.SetAutoPageBreak(true, 18)
	pdf.SetTitle(title, true)

	// Title page
	pdf.AddPage()
	pdf.SetFont("Times", "B", 18)
	pdf.MultiCell(0, 10, title, "", "C", false)
	pdf.Ln(4)
	pdf.SetFont("Times", "", 13)
	if strings.TrimSpace(author) != "" {
		pdf.MultiCell(0, 7, "Candidate: "+author, "", "C", false)
	}
	if strings.TrimSpace(institute) != "" {
		pdf.MultiCell(0, 7, institute, "", "C", false)
	}
	pdf.Ln(8)
	pdf.SetFont("Times", "I", 11)
	pdf.MultiCell(0, 6, "Generated from project sources", "", "C", false)

	// Content pages
	pdf.AddPage()
	pdf.SetFont("Times", "", 12)

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var paragraph strings.Builder
	flushParagraph := func() {
		text := strings.TrimSpace(paragraph.String())
		paragraph.Reset()
		if text == "" {
			pdf.Ln(3)
			return
		}
		pdf.SetFont("Times", "", 12)
		pdf.MultiCell(0, 6, text, "", "J", false)
		pdf.Ln(2)
	}

	writeHeading := func(level int, text string) {
		flushParagraph()
		size := 15
		style := "B"
		switch level {
		case 1:
			size = 16
		case 2:
			size = 14
		case 3:
			size = 13
			style = "B"
		default:
			size = 12
			style = "B"
		}
		pdf.SetFont("Times", style, float64(size))
		pdf.MultiCell(0, 8, text, "", "L", false)
		pdf.Ln(1)
		pdf.SetFont("Times", "", 12)
	}

	for s.Scan() {
		line := strings.TrimRight(s.Text(), " \t")
		if m := headingRE.FindStringSubmatch(line); len(m) == 3 {
			level := len(m[1])
			text := strings.TrimSpace(m[2])
			if text != "" {
				writeHeading(level, text)
			}
			continue
		}

		// Treat list markers as plain prose lines (the report content is prose-oriented).
		trim := strings.TrimSpace(line)
		if trim == "" {
			flushParagraph()
			continue
		}
		trim = strings.TrimPrefix(trim, "- ")
		trim = strings.TrimPrefix(trim, "* ")
		trim = strings.TrimPrefix(trim, "+ ")

		if paragraph.Len() > 0 {
			paragraph.WriteString(" ")
		}
		paragraph.WriteString(trim)
	}
	flushParagraph()

	if err := s.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := pdf.OutputFileAndClose(outPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(outPath)
}
