from xmlutils.xml2csv import xml2csv

converter = xml2csv("84218.nessus", "output.csv", encoding="utf-8")
converter.convert(tag="item")
