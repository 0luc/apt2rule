"""Countries and territories: the words that name them, and state agencies that imply attribution.

`terms` serve two purposes: the pipeline looks for them inside attribution phrases ("China-based",
"attributed to the Russian ..."), and threat2apt offers one target group per country to match victims.
Terms written in capitals (DPRK, PRC, US, UK, UAE) match case-sensitively, everything else ignores case.
Ambiguous words are left out on purpose: plain "Korean" (North or South?), "American" (Latin American?).
"""

# code, name, terms (name first)
_TABLE = """
AF|Afghanistan|Afghanistan;Afghan
AL|Albania|Albania;Albanian
DZ|Algeria|Algeria;Algerian
AD|Andorra|Andorra;Andorran
AO|Angola|Angola;Angolan
AG|Antigua and Barbuda|Antigua and Barbuda;Antiguan
AR|Argentina|Argentina;Argentine;Argentinian
AM|Armenia|Armenia;Armenian
AU|Australia|Australia;Australian
AT|Austria|Austria;Austrian
AZ|Azerbaijan|Azerbaijan;Azerbaijani
BS|Bahamas|Bahamas;Bahamian
BH|Bahrain|Bahrain;Bahraini
BD|Bangladesh|Bangladesh;Bangladeshi
BB|Barbados|Barbados;Barbadian
BY|Belarus|Belarus;Belarusian;Belorussian
BE|Belgium|Belgium;Belgian
BZ|Belize|Belize;Belizean
BJ|Benin|Benin;Beninese
BT|Bhutan|Bhutan;Bhutanese
BO|Bolivia|Bolivia;Bolivian
BA|Bosnia and Herzegovina|Bosnia and Herzegovina;Bosnia;Bosnian
BW|Botswana|Botswana;Botswanan
BR|Brazil|Brazil;Brazilian
BN|Brunei|Brunei;Bruneian
BG|Bulgaria|Bulgaria;Bulgarian
BF|Burkina Faso|Burkina Faso;Burkinabe
BI|Burundi|Burundi;Burundian
CV|Cabo Verde|Cabo Verde;Cape Verde;Cape Verdean
KH|Cambodia|Cambodia;Cambodian
CM|Cameroon|Cameroon;Cameroonian
CA|Canada|Canada;Canadian
CF|Central African Republic|Central African Republic
TD|Chad|Chad;Chadian
CL|Chile|Chile;Chilean
CN|China|China;Chinese;PRC;People's Republic of China
CO|Colombia|Colombia;Colombian
KM|Comoros|Comoros;Comorian
CG|Congo|Republic of the Congo;Congo-Brazzaville
CD|DR Congo|Democratic Republic of the Congo;DRC;Congolese
CR|Costa Rica|Costa Rica;Costa Rican
CI|Côte d'Ivoire|Côte d'Ivoire;Cote d'Ivoire;Ivory Coast;Ivorian
HR|Croatia|Croatia;Croatian
CU|Cuba|Cuba;Cuban
CY|Cyprus|Cyprus;Cypriot
CZ|Czechia|Czechia;Czech Republic;Czech
DK|Denmark|Denmark;Danish
DJ|Djibouti|Djibouti;Djiboutian
DM|Dominica|Dominica
DO|Dominican Republic|Dominican Republic;Dominican
EC|Ecuador|Ecuador;Ecuadorian
EG|Egypt|Egypt;Egyptian
SV|El Salvador|El Salvador;Salvadoran
GQ|Equatorial Guinea|Equatorial Guinea;Equatoguinean
ER|Eritrea|Eritrea;Eritrean
EE|Estonia|Estonia;Estonian
SZ|Eswatini|Eswatini;Swaziland
ET|Ethiopia|Ethiopia;Ethiopian
FJ|Fiji|Fiji;Fijian
FI|Finland|Finland;Finnish
FR|France|France;French
GA|Gabon|Gabon;Gabonese
GM|Gambia|Gambia;Gambian
GE|Georgia|Georgia;Georgian
DE|Germany|Germany;German
GH|Ghana|Ghana;Ghanaian
GR|Greece|Greece;Greek
GD|Grenada|Grenada;Grenadian
GT|Guatemala|Guatemala;Guatemalan
GN|Guinea|Guinea;Guinean
GW|Guinea-Bissau|Guinea-Bissau
GY|Guyana|Guyana;Guyanese
HT|Haiti|Haiti;Haitian
HN|Honduras|Honduras;Honduran
HK|Hong Kong|Hong Kong
HU|Hungary|Hungary;Hungarian
IS|Iceland|Iceland;Icelandic
IN|India|India;Indian
ID|Indonesia|Indonesia;Indonesian
IR|Iran|Iran;Iranian;Islamic Republic of Iran
IQ|Iraq|Iraq;Iraqi
IE|Ireland|Ireland;Irish
IL|Israel|Israel;Israeli
IT|Italy|Italy;Italian
JM|Jamaica|Jamaica;Jamaican
JP|Japan|Japan;Japanese
JO|Jordan|Jordan;Jordanian
KZ|Kazakhstan|Kazakhstan;Kazakh;Kazakhstani
KE|Kenya|Kenya;Kenyan
KI|Kiribati|Kiribati
XK|Kosovo|Kosovo;Kosovar
KW|Kuwait|Kuwait;Kuwaiti
KG|Kyrgyzstan|Kyrgyzstan;Kyrgyz
LA|Laos|Laos;Lao;Laotian
LV|Latvia|Latvia;Latvian
LB|Lebanon|Lebanon;Lebanese
LS|Lesotho|Lesotho
LR|Liberia|Liberia;Liberian
LY|Libya|Libya;Libyan
LI|Liechtenstein|Liechtenstein
LT|Lithuania|Lithuania;Lithuanian
LU|Luxembourg|Luxembourg;Luxembourgish
MG|Madagascar|Madagascar;Malagasy
MW|Malawi|Malawi;Malawian
MY|Malaysia|Malaysia;Malaysian
MV|Maldives|Maldives;Maldivian
ML|Mali|Mali;Malian
MT|Malta|Malta;Maltese
MH|Marshall Islands|Marshall Islands
MR|Mauritania|Mauritania;Mauritanian
MU|Mauritius|Mauritius;Mauritian
MX|Mexico|Mexico;Mexican
FM|Micronesia|Micronesia;Micronesian
MD|Moldova|Moldova;Moldovan
MC|Monaco|Monaco;Monegasque
MN|Mongolia|Mongolia;Mongolian
ME|Montenegro|Montenegro;Montenegrin
MA|Morocco|Morocco;Moroccan
MZ|Mozambique|Mozambique;Mozambican
MM|Myanmar|Myanmar;Burma;Burmese
NA|Namibia|Namibia;Namibian
NR|Nauru|Nauru
NP|Nepal|Nepal;Nepalese;Nepali
NL|Netherlands|Netherlands;Dutch
NZ|New Zealand|New Zealand
NI|Nicaragua|Nicaragua;Nicaraguan
NE|Niger|Niger
NG|Nigeria|Nigeria;Nigerian
KP|North Korea|North Korea;North Korean;DPRK;Democratic People's Republic of Korea
MK|North Macedonia|North Macedonia;Macedonia;Macedonian
NO|Norway|Norway;Norwegian
OM|Oman|Oman;Omani
PK|Pakistan|Pakistan;Pakistani
PW|Palau|Palau
PS|Palestine|Palestine;Palestinian
PA|Panama|Panama;Panamanian
PG|Papua New Guinea|Papua New Guinea
PY|Paraguay|Paraguay;Paraguayan
PE|Peru|Peru;Peruvian
PH|Philippines|Philippines;Philippine;Filipino
PL|Poland|Poland;Polish
PT|Portugal|Portugal;Portuguese
QA|Qatar|Qatar;Qatari
RO|Romania|Romania;Romanian
RU|Russia|Russia;Russian;Russian Federation
RW|Rwanda|Rwanda;Rwandan
KN|Saint Kitts and Nevis|Saint Kitts and Nevis
LC|Saint Lucia|Saint Lucia
VC|Saint Vincent and the Grenadines|Saint Vincent and the Grenadines
WS|Samoa|Samoa;Samoan
SM|San Marino|San Marino
ST|São Tomé and Príncipe|São Tomé and Príncipe;Sao Tome and Principe
SA|Saudi Arabia|Saudi Arabia;Saudi
SN|Senegal|Senegal;Senegalese
RS|Serbia|Serbia;Serbian
SC|Seychelles|Seychelles
SL|Sierra Leone|Sierra Leone
SG|Singapore|Singapore;Singaporean
SK|Slovakia|Slovakia;Slovak
SI|Slovenia|Slovenia;Slovenian
SB|Solomon Islands|Solomon Islands
SO|Somalia|Somalia;Somali
ZA|South Africa|South Africa;South African
KR|South Korea|South Korea;South Korean
SS|South Sudan|South Sudan
ES|Spain|Spain;Spanish
LK|Sri Lanka|Sri Lanka;Sri Lankan
SD|Sudan|Sudan;Sudanese
SR|Suriname|Suriname;Surinamese
SE|Sweden|Sweden;Swedish
CH|Switzerland|Switzerland;Swiss
SY|Syria|Syria;Syrian
TW|Taiwan|Taiwan;Taiwanese
TJ|Tajikistan|Tajikistan;Tajik
TZ|Tanzania|Tanzania;Tanzanian
TH|Thailand|Thailand;Thai
TL|Timor-Leste|Timor-Leste;East Timor
TG|Togo|Togo;Togolese
TO|Tonga|Tonga;Tongan
TT|Trinidad and Tobago|Trinidad and Tobago
TN|Tunisia|Tunisia;Tunisian
TR|Türkiye|Türkiye;Turkiye;Turkey;Turkish
TM|Turkmenistan|Turkmenistan;Turkmen
TV|Tuvalu|Tuvalu
UG|Uganda|Uganda;Ugandan
UA|Ukraine|Ukraine;Ukrainian
AE|United Arab Emirates|United Arab Emirates;UAE;Emirati
GB|United Kingdom|United Kingdom;UK;U.K.;Britain;British
US|United States|United States;US;U.S.;USA
UY|Uruguay|Uruguay;Uruguayan
UZ|Uzbekistan|Uzbekistan;Uzbek
VU|Vanuatu|Vanuatu
VA|Vatican City|Vatican City;Holy See
VE|Venezuela|Venezuela;Venezuelan
VN|Vietnam|Vietnam;Viet Nam;Vietnamese
YE|Yemen|Yemen;Yemeni
ZM|Zambia|Zambia;Zambian
ZW|Zimbabwe|Zimbabwe;Zimbabwean
"""

# State agencies whose mention attributes a group to their country on its own.
AGENCIES: dict[str, list[str]] = {
    "RU": ["GRU", "SVR", "FSB", "Main Intelligence Directorate", "Main Directorate of the General Staff",
           "Federal Security Service", "Foreign Intelligence Service of the Russian Federation",
           "Unit 26165", "Unit 74455", "Unit 29155"],
    "CN": ["MSS", "Ministry of State Security", "People's Liberation Army", "PLA", "Unit 61398", "Unit 61486",
           "Strategic Support Force"],
    "IR": ["IRGC", "Islamic Revolutionary Guard Corps", "MOIS", "Ministry of Intelligence and Security"],
    "KP": ["Reconnaissance General Bureau", "RGB"],
    "PK": ["Inter-Services Intelligence"],
}

COUNTRIES: list[dict] = []
for _line in _TABLE.strip().splitlines():
    _code, _name, _terms = _line.split("|")
    COUNTRIES.append({"code": _code, "name": _name, "terms": _terms.split(";")})

BY_CODE = {c["code"]: c for c in COUNTRIES}
assert len(BY_CODE) == len(COUNTRIES), "duplicate country code"
assert set(AGENCIES) <= set(BY_CODE), "agency for unknown country"
