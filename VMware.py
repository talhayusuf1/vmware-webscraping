import json
import requests
from bs4 import BeautifulSoup as bs
import re
from typing import List, Any
from selenium import webdriver
from time import sleep
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from datetime import timedelta
from packaging import version
from cvss import CVSS3
import os.path


class CveModel:
    code: str
    cve_mitre: str
    nist_nvd: str
    assigner: str
    published_date: str
    last_modified_date: str
    desc: str
    cwe: str
    vendor_confirmed: str
    vendor: List[str]
    target_product: List[str]
    vuln_version: List[Any]
    underlying_os: List[Any]
    advisory: List[Any]
    exploit_included: bool
    exploit: List[Any]
    fix_available: bool
    fix_url: List[str]
    references: List[Any]
    severity_score: str
    cvss3_score: str
    cvss3_vector: str

    def __init__(self, code: str):
        self.code = code
        self.cve_mitre = ""
        self.nist_nvd = ""
        self.assigner = ""
        self.published_date = ""
        self.last_modified_date = ""
        self.desc = ""
        self.cwe = ""
        self.vendor_confirmed = ""
        self.vendor = []
        self.target_product = []
        self.vuln_version = []
        self.underlying_os = []
        self.advisory = []
        self.exploit_included = True
        self.exploit = []
        self.fix_available = True
        self.fix_url = []
        self.references = []
        self.severity_score = ""
        self.cvss3_score = ""
        self.cvss3_vector = ""

    def setTableValues(self, product: str, versionInfo: str, fixedVersionInfo: str, runningOn: str, fixedVersionUrl: str,):
        # hedeflenen ürün kontrol edildikten sonra eğer zaten ekli ise target listesinden productın indexini alıp versiyonu, os bilgisini ve fixed versiyon url'ni ilgili modele ekleme işlemi yapilir
        excludedVersions = ["Nopatchplanned", "notaffected", "Notaffected", "Notaffected.", "Patchpending",
                            "PatchPending", "PatchPending[1]", "PatchPlanned", "SeeResolutionsection", "Unaffected"]  # bu versiyon tipleri geldiğinde o ürünü almıyoruz
        # Urun bilgisi istenmeyen koseli parantezden kurtarilir
        target = product.split("[")[0].rstrip()
        isExcluded = False
        for ex in excludedVersions:  # Istenmeyen versiyon kontrolu
            if fixedVersionInfo == ex:
                isExcluded = True
        if not isExcluded:
            if target in self.target_product:  # productın cve modelde önceden eklenmis olmasi durumunda ilgili kontroller yapilir
                # zaten kayıtlı olan productın liste indexi erişim için alınır
                index = self.target_product.index(target)
                checkedFixVer = checkVersion(
                    verInfo=fixedVersionInfo, isFix=True)  # fix versiyon bilgisinin istenilen formattaysa string değer alınır
                self.vuln_version[index]
                vuln_ver = []
                # cvenin kayıtlı producta ekleme yapılabilmesi için eğer string halinde tutuluyorsa
                if type(self.vuln_version[index]) == str:
                    # yeni versiyon ve diğer bilgilerin eklenebilmesi için listeye çevirilir
                    vuln_ver = [self.vuln_version[index]]
                else:
                    # liste olduğu durumlarda versiyon bilgisi direkt eşitlenir
                    vuln_ver = self.vuln_version[index]
                if type(checkedFixVer) is str:  # istenilen formatta fix versiyon bilgisi varsa
                    # versiyon bilgisi kontrol edilir
                    checkedVer = checkVersion(verInfo=versionInfo, isFix=False)
                    # hem versiyonun hem fix versiyonun standart versyon formatta olması durumunda fix versiyon bilgiside mevcut versyonlara eklenir
                    vuln_ver.append(checkedVer + checkedFixVer)
                    # işleme alınmış versiyon bilgileri modele aktarılır
                    self.vuln_version[index] = vuln_ver
                else:  # fix versiyon bilgisinin standart formda olmadığı durumlarda
                    if "," in versionInfo:  # eğer birden fazla versiyon varsa
                        # mevcut versiyon bilgileri yeni versiyonlarda genişletilir
                        vuln_ver.extend(versionInfo.split(","))
                        self.vuln_version[index] = vuln_ver
                    else:  # tekil olduğu durumda mevcut listeye eklenir
                        vuln_ver.append(versionInfo)
                        self.vuln_version[index] = vuln_ver
                # modeldeki mevcut os bilgisi alınır
                currentRunningOn = self.underlying_os[index]
                if not runningOn in currentRunningOn:  # unique olması için kontroller sağlanarak eklenir
                    currentRunningOn.append(runningOn)
                # model os bilgisi güncellenir
                self.underlying_os[index] = currentRunningOn
                # fixed versiyon linki 'None' durumunda modelin fix versyionlarına eklenmez
                if not "None" in str(fixedVersionUrl):
                    self.advisory.append(fixedVersionUrl)
            else:  # product daha önce modele eklenmediyse ilgili bilgiler modele eklenir
                self.target_product.append(target)
                checkedFixVer = checkVersion(
                    verInfo=fixedVersionInfo, isFix=True)
                vuln_ver = []
                if type(checkedFixVer) is str:
                    checkedVer = checkVersion(verInfo=versionInfo, isFix=False)
                    vuln_ver.append(checkedVer + checkedFixVer)
                    self.vuln_version.append(vuln_ver)
                else:
                    if "," in versionInfo:
                        vuln_ver = (versionInfo.split(","))
                        self.vuln_version.append(vuln_ver)
                    else:
                        vuln_ver = [versionInfo, ]
                        self.vuln_version.append(vuln_ver)
                self.underlying_os.append([runningOn])
                if not "None" in str(fixedVersionUrl):
                    self.advisory.append(fixedVersionUrl)

# Bu metotta verdiğimiz vectorun severity si ve score unu buluyor


def setCvssValues(vector: str, model: CveModel):
    try:
        c = CVSS3(vector)
        model.cvss3_vector = vector
        model.cvss3_score = str(c.base_score)
        model.severity_score = c.severities()[0]
    except Exception as e:
        print("Hata oluştu:", e)
# Versiyon bilgisini istenilen standartlara çevirir


def checkVersion(verInfo: str, isFix: bool):
    ver = verInfo
    if "and" in ver:
        ver = ver.replace("and", ",")
    if "*" in ver:
        ver = ver.replace("*", "")
    if '.x' in ver:
        ver = ver.replace(".x", ".0")
    if '.y' in ver:
        ver = ver.replace(".y", ".0")
    if "KB" in ver:  # alınan versiyonun KB içermesi durumunda istenilen düzenlemeler yapılır
        if "(" in ver:
            parsedVer = ver.split("(")[1]
            if ')' in parsedVer:
                parsedVer.replace(')', '')
                # "KBXXXX(a.b.c)" şeklinde gelen versiyonlarda parantezin içerisndeki versiyon bilgisinin versiyon formatında olup olmadıgı teyit edilir
                if isinstance(ver.parse(parsedVer), version.Version):
                    if isFix:  # Eger çalışılan versiyon bilgisi fixed versiyon içinse excluding ibaresi yazılır
                        return ver + ' (excluding)'
                    else:
                        return ver + '(including) - '
        else:
            return ver
    if ',' in ver:  # Çoklu versiyon verilmesi durumunda en küçük versiyon tespit edilir
        versionList = ver.split(",")
        oldestVer = '1000.0.0.0'
        for v in versionList:
            # eğer numerik olmayan karakterler var ise düzenlenmiş versiyonu döndürür
            if not v.replace('.', '').isnumeric():
                if not isFix:  # Bütün metotta fixed versiyonun sadece istenilen durumda versiyon bilgisine dahil edilmesinden emin olunulur
                    return ver
            # versiyon bilgisinin versiyon formatında olup olmadıgı teyit edilir
            if isinstance(version.parse(v), version.Version):
                if int(v.split(".")[0]) < int(oldestVer.split(".")[0]):
                    oldestVer = v
                elif int(v.split(".")[0]) == int(oldestVer.split(".")[0]):
                    if int(v.split(".")[1]) < int(oldestVer.split(".")[1]):
                        oldestVer = v
                    elif int(v.split(".")[1]) == int(oldestVer.split(".")[1]):
                        if int(v.split(".")[2]) < int(oldestVer.split(".")[2]):
                            oldestVer = v
                        elif int(v.split(".")[2]) == int(oldestVer.split(".")[2]):
                            if int(v.split(".")[3]) < int(oldestVer.split(".")[3]):
                                oldestVer = v
            else:  # Eger versiyon formatında değilse düzenlenmiş versiyon donulur
                if not isFix:
                    return ver
        # Bulunan en küçük versiyonu imcluding yapılır
        if isinstance(version.parse(oldestVer), version.Version):
            return oldestVer + ' (including) - '
    # Versiyon bilgisinin tek olması durumunda versiyon formatına uyup uymadığı kontrol edilir.
    if isinstance(version.parse(ver), version.Version):
        if isFix:
            return ver + ' (excluding)'
        else:
            return ver + ' (including) - '
    else:
        if not isFix:
            return ver


def returnUnderLyingOs(os: str):
    if os == "Any":
        return "*"
    else:
        return os


def getDictionaries(days: int,):
    advisory_url = "https://www.vmware.com/security/advisories.html"
    # Ilk calismada yeni bultenlerin kontrol edilecegi tarih
    last_control_date = datetime.date.today()-timedelta(days=days)
    # tarih kontrolü yapılan son kontrolün tarihi json dosyasından çekilerek sağlanır
    firefox_options = webdriver.FirefoxOptions()
    firefox_options.headless = True
    browser = webdriver.Firefox(
        executable_path="C://Depo//Project//Vmware//geckodriver.exe", options=firefox_options)
    exploit_list = []  # Scrap edilecek exploitlerin bulunduğu liste
    exploit_dict_list = []  # Exploitlerin islendikten sonra kayit edildigi yer
    # Son kontrolden itibaren yeni gelen bültenlerin kontrol edilecegi siteye istek atılır
    browser.get(advisory_url)
    sleep(10)
    soup = bs(browser.page_source, "html.parser")
    html_table = soup.find("tbody")  # Bultenlerin bulundugu tabloya erişlir
    rows = html_table.find_all("tr")  # Tablodan satirlar cekilir
    columns = []
    for row in rows:
        columns = row.find_all("td")  # Her bir satirdaki sutunlar cekilir
        exploit = columns[0].find("a").text  # Bulten isminin bulundugu sutun
        exploit_date = columns[3].text  # Bulten tarihinin bulundugu sutun
        # Bulten tarihi kontrol edilebilmesi icin parse edilir
        parsed_date = exploit_date.split("-")
        # Son kontrol tarihi kiyas edilebilmesi icin parse edilir
        parsed_latest_control = str(last_control_date).split("-")
        exploit_date = datetime.date(int(parsed_date[2]), int(
            parsed_date[1]), int(parsed_date[0]))  # "-" ile ayrılan tarihi datetime objesine çeviriyoruz

        if exploit_date > last_control_date:  # Eger yeni bir bulten geldiyse kontrol listesine eklenir
            exploit = exploit.strip(" ")
            exploit_list.append(exploit)

    for exploit in exploit_list:  # Yeni gelen bultenlerin bulunudugu listedeki her bir bulten için
        cveModelList = []  # cve modellerinin  tutuldugu liste
        exploit_url = "https://www.vmware.com/security/advisories/{}.html".format(
            exploit)  # bultenin adresi formatlanir
        exploit_response = requests.get(exploit_url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64"})
        # Yayinlanma tarihi ve guncelleme tarihi çekilir
        parsed_exploit = bs(exploit_response.text, "html.parser")
        # Sayfanin basindaki basliklar cekilir
        top_headers = parsed_exploit.find_all("div", {"class": "sa-row-group"})
        # Buradan yayınlanma tarihi gelir
        issue_date = re.sub('\s+', '', top_headers[2].text).split("Date:")
        # Burdan ise güncellenme tarihi gelir
        update_date = re.sub('\s+', '', top_headers[3].text).split("On:")
        # Yayinlanma tarihi icin Yil ay gün seklinde datetime objesine cevrilmesi ayni islemler yapilir
        parsed_issue = (issue_date[1]).split("-")
        issueDatetime = datetime.datetime(int(parsed_issue[0]), int(
            parsed_issue[1]), int(parsed_issue[2])).isoformat()
        parsed_update = (update_date[1].split("(")[0]).split(
            "-")  # Guncellenme tarihi icin islemler tekrar edilir
        updateDatetime = datetime.datetime(int(parsed_update[0]), int(
            parsed_update[1]), int(parsed_update[2])).isoformat()
        # Bultendeki cve'ler cekilir
        cve_header = parsed_exploit.find(
            "div", {"class": "sa-details"}).find_all("span")  # Sitenin giris kismindanki cve'ler bulunur
        top_header_details = []
        for item in cve_header:
            top_header_details.append(item.text.strip(" "))
        cve_list = []  # cve'lerin bulundugu liste
        # cve'lerin bulundugu liste cekilir
        cve_list = re.sub('\s+', '', top_header_details[4]).split(",")
        header_list = []  # cve'lerin aciklamlarinin  altinda bulunan basliklar bulunur
        header_response = parsed_exploit.find_all(
            "div", {"class": "secadvheading aem-GridColumn aem-GridColumn--default--12"})  # Tüm basliklar alınır
        for i in header_response:  # baslıklar header liste eklenir
            header_list.append(i.text.strip())
        for i in header_list:
            for c in cve_list:
                if c in i:  # Eger kontrol edilen baslikta hedeflenen cve var ise bilgiler cekilir
                    # Basligin altindaki bilgilere ulasmak icin header response da dolasmak üzere basligin indexi alinir
                    h_index = header_list.index(i)
                    h_index = h_index+1
                    detail = re.sub(
                        '\s+', ' ', header_response[h_index].find_next_sibling().text[1:])  # Detail alinir
                    # Buraya kadar description bilgisi alınır
                    description = detail.split(" VMware has evaluated")
                    # Alinan bilgiler düzenlenmek üzere modele kaydedilir
                    cve = CveModel(code=c)
                    cve.fix_url.append(exploit_url)  # Bulten linki eklenir
                    cve.desc = description[0]
                    cveModelList.append(cve)  # Model bu listeye dahil edilir

        # Bu metotta işletim sisteminde eger any varsa  * la deiştiriyoruz

        table_resp = parsed_exploit.find_all(
            "div", {"class": "advisories-data aem-GridColumn aem-GridColumn--default--12"})  # Urun bilgilerinin cekilmesi icin butun tablolar elde edilir
        for table in table_resp:
            rows = table.find_all("tr")
            for row in rows:
                contents = row.find_all("td")  # Satirdaki sutunlari bulur
                cveIdentifier = re.sub('\s+', '', contents[3].text)
                product = contents[0].text.strip()
                verInfo = re.sub('\s+', '', contents[1].text)
                runningOn = re.sub('\s+', '', contents[2].text)
                cvssv3 = re.sub('\s+', '', contents[4].text)
                fixedVersion = re.sub('\s+', '', contents[6].text)
                fixedVersionUrlInfo = contents[6].find("a")
                if str(type(fixedVersionUrlInfo)) == "<class 'bs4.element.Tag'>":
                    # Eger fix versiyon link içeriyorsa linki alinir
                    fixedVersionUrlInfo = fixedVersionUrlInfo['href']
                for c in cve_list:
                    if c in cveIdentifier:  # cve listesindeki ile satirdaki cve'ler eşlesirse
                        for item in cveModelList:
                            if item.code in c:  # eger suan kontrol edilen cve listedekine esitse ilgili bilgiler modele yazilir
                                item.setTableValues(product=product,
                                                    versionInfo=verInfo, fixedVersionInfo=fixedVersion,
                                                    runningOn=returnUnderLyingOs(
                                                        os=runningOn),
                                                    fixedVersionUrl=str(
                                                        fixedVersionUrlInfo),
                                                    )

        # sayfadan vectorler cekilir
        for i in parsed_exploit.find_all('a', href=re.compile("^https://")):
            # "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" linkin kontrolu yapilir
            if 'calculator' in i['href']:
                for model in cveModelList:
                    if model.code in i.previous_element:  # Eger kontrol edilen modelin cve kodu linkin basliginda yer aliyorsa
                        vector = i.get_text().split("#")[1]
                        # vector modele kaydedilir
                        setCvssValues(vector=vector, model=model)
                    else:
                        continue

        for model in cveModelList:
            model.cve_mitre = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={}".format(
                str(model.code))  # cve mitre eklenir
            model.nist_nvd = "https://nvd.nist.gov/vuln/detail/{}".format(
                str(model.code))  # nist_nvd eklenir
            # published date istenilen formata getirilir
            model.published_date = {
                "__type": "Date", "iso": issueDatetime+".000Z"}
            model.last_modified_date = {
                "__type": "Date", "iso": updateDatetime+".000Z"}  # Last modifed date istenilen formata getirilir

            for i in range(len(model.target_product)):
                # Urun sayisi kadar vendor eklenir
                model.vendor.append("VMware")

        dict_list = []
        for cve in cveModelList:
            cve.advisory = list(set(cve.advisory))
            vmwareDict = {
                "code": cve.code,
                "cveMitre": cve.cve_mitre,
                "nistNVD": cve.nist_nvd,
                "assigner": "security@vmware.com",
                "publishedDate": cve.published_date,
                "lastModifiedDate": cve.last_modified_date,
                "desc": cve.desc,
                "cwe": [],
                "vendorConfirmed": True,
                "vendor": cve.vendor,
                "target": cve.target_product,
                "vulnVersion": cve.vuln_version,
                "underlyingOS": cve.underlying_os,
                "advisory": cve.advisory,
                "exploitIncluded": False,
                "exploit": [],
                "fixAvailable": True,
                "fixURL": cve.fix_url,
                "references": [],
                "severityScore": cve.severity_score,
                "cvss3Score": cve.cvss3_score,
                "cvss3Vector": cve.cvss3_vector
            }
            dict_list.append(vmwareDict)
        # dictionaryler ana listeye kayıt edilir
        exploit_dict_list.append(dict_list)

    browser.quit()
    # return exploit_dict_list
    json_data = json.dumps(exploit_dict_list)
    with open("data.json", "w") as f:
        f.write(json_data)
    return json_data
    print('IM DONE')


print(getDictionaries(days=20))
