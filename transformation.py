import json
from fpdf import FPDF

sayac = 1
with open('data.json', 'r') as f:
    data = json.load(f)


class PDF(FPDF):
    def header(self):
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Calculate width of title and position
        title_w = self.get_string_width("Guncel Bulten Raporlari") + 6
        self.set_text_color(0, 0, 255)
        doc_w = self.w
        self.set_x((doc_w - title_w) / 2)
        # Title
        self.cell(title_w, 10, 'Guncel Bulten Raporlari',
                  border=0, ln=1, align='C')

    def create_report(self, items, number):
        for item in items:
            self.add_page()
            self.set_font("Helvetica", style="B", size=10)
            self.cell(35, 10, "Code:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['code']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "cveMitre:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['cveMitre']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "nistNVD:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['nistNVD']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "assigner:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['assigner']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "publishedDate:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['publishedDate']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "lastModifiedDate:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['lastModifiedDate']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "desc:", ln=0)
            self.set_text_color(255, 0, 0)
            self.multi_cell(0, 10, f"{item['desc']}")
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "cwe:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['cwe']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "vendorConfirmed:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['vendorConfirmed']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "vendor:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['vendor']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "target:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['target']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "vulnVersion:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['vulnVersion']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "underlyingOS:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['underlyingOS']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "advisory:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['advisory']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "exploitIncluded:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['exploitIncluded']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "exploit:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['exploit']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "fixAvailable:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['fixAvailable']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "fixURL:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['fixURL']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "severityScore:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['severityScore']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "cvss3Score:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['cvss3Score']}", ln=1)
            self.set_text_color(0, 0, 0)
            self.cell(35, 10, "cvss3Vector:", ln=0)
            self.set_text_color(255, 0, 0)
            self.cell(0, 10, f"{item['cvss3Vector']}", ln=1)
            self.set_text_color(0, 0, 0)
        self.output(str(number)+". Bulten.pdf")


for veriler in data:

    pdf = PDF()
    pdf.create_report(veriler, sayac)
    sayac = sayac+1

# self.multi_cell(0, 4, f"desc: {item['desc']}")
    # self.ln()
