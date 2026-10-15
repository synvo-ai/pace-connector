"""Realistic English enquiry emails for measuring the privacy check.

Two rates matter and both are measured:
- blocked: an ordinary email that the egress check stops, so it goes to Manual handling;
- missed: a person's name that leaves the connector unmasked.

`dev_cases` is the 9 Oct mock emails, two samples shaped like real integration traffic (a
signature with name, job title and company; a Microsoft Graph follow-up) and the connector
examples; the fix was tuned on it. `HELD_OUT` was written on 15 Oct before the fix; three small fixes were made
after its first run, so it is no longer clean. `HARD` was written after the fix, aimed at
the weak spots (names inside sentences, names that are English words, lower-case names), and
run once without tuning.
All names, addresses and numbers are made up.

Each case: (case_id, sender, subject, body, names). `names` lists every person named in the
subject or the current body; quoted history is cut by the parser and is not sent. A name given
as (name, n) also appears n times as an ordinary word ("May intake").
"""

from __future__ import annotations

from email.message import EmailMessage
import hashlib
import json
from pathlib import Path

MOCK_EML = Path(__file__).resolve().parent / "mock_emails"
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

# Names in the current message of each English single-message mock email (9 Oct pack).
MOCK_NAMES: dict[str, tuple[str, ...]] = {
    "A1-01": ("Rachel Lim",), "A1-02": ("Marcus",), "A1-03": ("Aisyah",), "A2-01": ("Priya Ramasamy",),
    "A2-02": ("Daniel Koh",), "A3-01": ("Marcus Tan",), "A3-02": ("Helen Wong",), "A3-03": ("Joseph Lee",),
    "A4-01": ("Kelvin",), "A4-02": ("Siti",), "A5-01": ("Wei Jie",), "A6-01": ("Tan Wei Ming",),
    "A7-01": ("Rachel",), "A9-01": ("Grace Ho",), "A9-02": (), "E8-01": ("Lim Hui Min",), "E8-02": ("Ben",),
}

SIGNATURE_SAMPLE = (
    "sample-signature", "Camellia Ong Hui Shan <camellia@brightpath.example>", "Demo - Enquiry about AI Ethics",
    "Dear NTU PACE Admissions Team,\n\nI am writing to inquire about the course \"Addressing Issues in AI Ethics and Governance (Synchronous and Asynchronous E-Learning).\"\n\n"
    "Could you please provide the upcoming intake schedule, enrollment deadlines, and the full breakdown of fees or available funding options for this course?\n\n"
    "Thank you for your assistance.\n\nThanks & Regards,\n\nCamellia Ong Hui Shan | Data Analyst | Brightpath Consulting\n"
    "Email: camellia@brightpath.example Website: www.brightpath.example",
    ("Camellia Ong Hui Shan",),
)

# A Microsoft Graph follow-up, reduced to the fields the connector reads.
GRAPH_SAMPLE = {
    "id": "sample-graph-followup", "subject": "Re: Enquiry about Biomaterials course",
    "body": {"contentType": "html", "content": "<html><body><div dir=\"ltr\">Dear Jun Hao,<br><br>Thank you for the details.<br><br>I would like to know more about the scholarship options available for this course. Could you share some information regarding that, or point me in the right direction?<br><br>Thanks &amp; Regards,<br>Mei Xuan Koh<br><br></div><br><div class=\"gmail_quote gmail_quote_container\"><div dir=\"ltr\" class=\"gmail_attr\">On Wed, Aug 26, 2026 at 12:59 PM Jun Hao Lim &lt;junhao@pace-mock.example&gt; wrote:<br></div><blockquote class=\"gmail_quote\"><div>Dear Mei Xuan Koh,<br><br>Thank you for your enquiry regarding the Biomaterials (Asynchronous e-learning) course.<br><br>Warm regards,<br>NTU PACE Enquiries </div></blockquote></div></body></html>"},
    "from": {"emailAddress": {"name": "Mei Xuan Koh", "address": "meixuan.koh@example.test"}},
    "toRecipients": [{"emailAddress": {"name": "Jun Hao Lim", "address": "junhao@pace-mock.example"}}],
}

HELD_OUT: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    ("H01", "Nurul Huda binte Ismail <nurul.huda@example.test>", "Enquiry on Specialist Diploma in Supply Chain Management",
     "Dear Sir/Madam,\n\nMy name is Nurul Huda binte Ismail and I work as an Operations Executive at a shipping firm. I would like to apply for the Specialist Diploma in Supply Chain Management starting in March 2027.\n\nCould you let me know the entry requirements and whether my Diploma in Business Studies from Ngee Ann Polytechnic is accepted?\n\nThank you.\n\nRegards,\nNurul Huda", ("Nurul Huda binte Ismail",)),
    ("H02", "Arjun s/o Krishnan <arjun.k@example.test>", "SkillsFuture Mid-Career Enhanced Subsidy",
     "Hi PaCE Team,\n\nI am 45 years old. Am I eligible for the SkillsFuture Mid-Career Enhanced Subsidy for the Graduate Certificate in Fintech? How much would I pay after the subsidy?\n\nThanks,\nArjun", ("Arjun",)),
    ("H03", "Chloe Teo <chloe.teo@example.test>", "Change of email address",
     "Hello,\n\nI am a current student in the Professional Certificate in Digital Marketing (Class DM-2026-09). Please update my email address to chloe.teo.new@example.test. My student ID is U2612345K.\n\nBest regards,\nChloe Teo", ("Chloe Teo",)),
    ("H04", "Mohamed Rizwan <rizwan.m@example.test>", "Request for certificate of completion",
     "Dear PaCE Admin,\n\nI completed the Certificate in Python for Data Analysis in June 2026 but have not received my e-certificate. Could you please check?\n\nRegards,\nMohamed Rizwan\nSenior Analyst, Changi Logistics Pte Ltd\nTel: 6123 4567", ("Mohamed Rizwan",)),
    ("H05", "Lee Jia Hui <jiahui.lee@example.test>", "Class timing",
     "Hi,\n\nAre the classes for the FlexiMasters in Data Science held on weekday evenings or on Saturdays? I work shifts at Tan Tock Seng Hospital so I need to plan ahead.\n\nThank you\nJia Hui", ("Jia Hui",)),
    ("H06", "Samantha Rodrigues <sam.rod@example.test>", "Question about my application",
     "Dear Ms Wong,\n\nThank you for speaking with me on the phone yesterday. As discussed, I have now uploaded my degree scroll and transcript to the application portal. Please let me know if anything else is needed.\n\nKind regards,\nSamantha Rodrigues", ("Ms Wong", "Samantha Rodrigues")),
    ("H07", "Zhang Wei <zhang.wei@example.test>", "Company sponsorship letter",
     "Hello PaCE,\n\nMy employer, Keppel Offshore and Marine, will sponsor my enrolment in the Graduate Diploma in Project Management. Our HR manager, Jasmine Ong, would like to know what documents she needs to provide and who she should send them to.\n\nThanks and regards,\nZhang Wei", ("Jasmine Ong", "Zhang Wei")),
    ("H08", "Faridah Abdullah <faridah.a@example.test>", "Refund status",
     "Good morning,\n\nI withdrew from the Advanced Certificate in Early Childhood Care and Education on 1 September 2026. I was told the refund would take four weeks but I have not received it yet. Could you check on it?\n\nThank you,\nFaridah", ("Faridah",)),
    ("H09", "Ong Boon Keat <bk.ong@example.test>", "Deferment",
     "Dear Admissions Office,\n\nI was offered a place in the MSc in Financial Technology for the January 2027 intake. Due to a work posting to Jakarta, I would like to defer to August 2027. Is this possible?\n\nYours faithfully,\nOng Boon Keat", ("Ong Boon Keat",)),
    ("H10", "Vanessa Lim <vanessa.lim@example.test>", "Group registration for 15 staff",
     "Hi there,\n\nI am from the People Development team at Singapore Power. We would like to register 15 engineers for the Professional Certificate in Electric Vehicle Technology. Do you offer corporate rates, and can we pay by GIRO?\n\nCheers,\nVanessa Lim\nHR Business Partner | Singapore Power", ("Vanessa Lim",)),
    ("H11", "Rahul Menon <rahul.menon@example.test>", "Prerequisites for Deep Learning module",
     "Hello,\n\nI have a Bachelor of Engineering (Mechanical) from NUS. Do I need to complete Introduction to Machine Learning before taking Deep Learning for Computer Vision, or can I take them together?\n\nThanks!\nRahul", ("Rahul",)),
    ("H12", "Emily Chua <emily.chua@example.test>", "Lost my login",
     "Dear PaCE,\n\nI cannot log in to the NTU Learn portal. I tried resetting my password but did not get the reset email. My username is emilychua88.\n\nRegards,\nEmily", ("Emily",)),
    ("H13", "Goh Siew Ling <siewling.goh@example.test>", "Enquiry - Executive Certificate in Healthcare Leadership",
     "Dear Sir or Madam,\n\nI am a Nurse Manager at Khoo Teck Puat Hospital. I am interested in the Executive Certificate in Healthcare Leadership. Is there a hospital sponsorship scheme through MOH Holdings?\n\nWarm regards,\nGoh Siew Ling (Ms)", ("Goh Siew Ling",)),
    ("H14", "Kumaravel Pillai <kumar.p@example.test>", "Payment by instalments",
     "Hi,\n\nCan I pay the fees for the Specialist Diploma in Cloud Computing in instalments? I would prefer monthly payments.\n\nThank you,\nKumar", ("Kumar",)),
    ("H15", "Isabelle Fernandez <isabelle.f@example.test>", "Appeal for late submission",
     "Dear Dr Ramesh,\n\nI am writing to appeal for an extension for my final assignment in Strategic Marketing Management. I was hospitalised from 3 to 8 October and have attached my medical certificate.\n\nSincerely,\nIsabelle Fernandez", ("Dr Ramesh", "Isabelle Fernandez")),
    ("H16", "Tan Ah Kow <ahkow.tan@example.test>", "Senior learner",
     "Hello\n\nI am 62 and retired. Are there courses for seniors like me in Digital Literacy? My daughter Mei Fen said NTU has some.\n\nThanks\nAh Kow", ("Mei Fen", "Ah Kow")),
    ("H17", "Alicia Ng <alicia.ng@example.test>", "Exemption for Statistics module",
     "Hi PaCE,\n\nI took Statistics for Business at SMU in 2022 and got an A. Can I be exempted from Applied Statistics in the Graduate Certificate in Business Analytics?\n\nBest,\nAlicia", ("Alicia",)),
    ("H18", "Hafiz Rahman <hafiz.rahman@example.test>", "Course venue",
     "Dear PaCE team,\n\nWhere will the Certificate in Sustainable Urban Design be held, at the One-North campus or at Yunnan Garden? And is there parking?\n\nThank you\nHafiz Rahman", ("Hafiz Rahman",)),
    ("H19", "Wong Kar Mun <karmun.w@example.test>", "Fees for international students",
     "Hello,\n\nI am a Malaysian working in Singapore on an Employment Pass. Are the fees for the Graduate Certificate in Cybersecurity Management different for me? Am I eligible for any funding?\n\nRegards,\nKar Mun", ("Kar Mun",)),
    ("H20", "Daniel Seah <daniel.seah@example.test>", "Recommendation from Prof Lee",
     "Dear Admissions Team,\n\nProfessor Lee Kok Hong suggested I contact you about the Master of Science in Artificial Intelligence. I graduated from NTU EEE in 2021. When does the next intake open?\n\nThank you,\nDaniel Seah", ("Lee Kok Hong", "Daniel Seah")),
    ("H21", "noreply <noreply@example.test>", "Course enquiry from website form",
     "Name: Priscilla Yeo\nEmail: priscilla.yeo@example.test\nPhone: 9234 5678\nCourse: Professional Certificate in Data Visualisation\nMessage: Is this course SkillsFuture claimable and are there online classes?", ("Priscilla Yeo",)),
    ("H22", "Joanne Lau <joanne.lau@example.test>", "Waiting list",
     "Hi,\n\nThe February run of the Certificate in UX Design is full. Can you put me on the waiting list? Please contact me at 8765 4321.\n\nJoanne", ("Joanne",)),
    ("H23", "Ravi Shankar <ravi.shankar@example.test>", "Course materials",
     "Dear PaCE,\n\nWill the slides for the Blockchain for Business module be available after the course ends? Our instructor, Mr Benedict Tay, said we should ask the office.\n\nThanks,\nRavi", ("Benedict Tay", "Ravi")),
    ("H24", "Lim Pei Shan <peishan.lim@example.test>", "Re: Your enquiry",
     "Thanks for the information. Just one more question: is the April run conducted in person or via Zoom?\n\nPei Shan", ("Pei Shan",)),
    ("H25", "Gabriel Tan <gabriel.tan@example.test>", "Recognition of prior learning",
     "Hello,\n\nI hold the WSQ Advanced Certificate in Training and Assessment. Does this count towards the Specialist Diploma in Learning Design and Technology?\n\nRegards,\nGabriel", ("Gabriel",)),
    ("H26", "Hui Min <huimin@example.test>", "Fee breakdown",
     "Dear Sir,\n\nCould you send me the full fee breakdown, including GST, for the Graduate Certificate in Marine Engineering? My company, PSA International, needs it for approval.\n\nBest regards,\nHui Min", ("Hui Min",)),
    ("H27", "Christopher Low <chris.low@example.test>", "Unable to attend Saturday class",
     "Hi,\n\nI will miss the class on Saturday 7 November due to reservist duty (In-Camp Training). Is there a make-up session? I can show my NS notice.\n\nThanks\nChris Low", ("Chris Low",)),
    ("H28", "Aminah Yusof <aminah.y@example.test>", "Transcript request",
     "Dear Registry,\n\nI need an official transcript for the Graduate Diploma in Counselling, which I completed in 2024, for my application to the Singapore Association for Counselling. How do I request one?\n\nThank you,\nAminah Yusof", ("Aminah Yusof",)),
    ("H29", "Peter Kwok <peter.kwok@example.test>", "Apple Developer Academy course",
     "Hello,\n\nDo you still run the iOS App Development with Swift course with Apple? I could not find it on the website this year.\n\nRegards,\nPeter", ("Peter",)),
    ("H30", "Shalini Nair <shalini.nair@example.test>", "Scholarship for women in tech",
     "Dear PaCE,\n\nI read about the Women in Tech scholarship on LinkedIn. Does it apply to the Professional Certificate in Cloud Architecture, and how do I apply?\n\nMany thanks,\nShalini Nair", ("Shalini Nair",)),
    ("H31", "Marcus Wee <marcus.wee@example.test>", "Upgrade from certificate to diploma",
     "Hi,\n\nI finished the Graduate Certificate in Digital Transformation last year. Can its modules be stacked towards the Graduate Diploma in Digital Transformation, and is there a deadline?\n\nBest regards\nMarcus Wee\nAssistant Director, Ministry of Manpower", ("Marcus Wee",)),
    ("H32", "Ho Yan Ting <yanting.ho@example.test>", "Change of class",
     "Dear PaCE,\n\nCan I switch from the Tuesday class to the Thursday class for Financial Accounting Fundamentals? My manager, Mr Lim, has changed my roster.\n\nThank you,\nYan Ting", ("Mr Lim", "Yan Ting")),
    ("H33", "Benjamin Ang <ben.ang@example.test>", "Overseas study trip",
     "Hello,\n\nThe brochure for the Executive Master of Business Administration mentions a study trip to Silicon Valley. Is the cost included in the programme fee?\n\nRegards,\nBenjamin Ang", ("Benjamin Ang",)),
    ("H34", "Ng Li Ting <liting.ng@example.test>", "Missing invoice",
     "Hi PaCE Finance,\n\nOur company paid invoice INV-2026-0912 for the Leadership Essentials programme, but we need a tax invoice addressed to Jurong Town Corporation. Can you reissue it?\n\nThanks,\nLi Ting\nFinance Executive", ("Li Ting",)),
    ("H35", "Siti Nurhaliza <siti.n@example.test>", "Course for my staff",
     "Dear Madam/Sir,\n\nI run a small bakery in Tampines and would like to send two staff to a Food Safety Management course. Do you offer anything suitable?\n\nTerima kasih and regards,\nSiti", ("Siti",)),
    ("H36", "Kevin Lim <kevin.lim@example.test>", "Online exam rules",
     "Hi,\n\nFor the online final exam of Data Structures and Algorithms, are we allowed to use notes? Dr Tan didn't mention it in class.\n\nKevin", ("Dr Tan", "Kevin")),
    ("H37", "Irene Koh <irene.koh@example.test>", "Thank you",
     "Dear PaCE Team,\n\nJust a short note to thank you and especially Ms Farah from the enquiries desk for helping me with my application last week. I have now received my offer letter.\n\nWarm regards,\nIrene", ("Ms Farah", "Irene")),
    ("H38", "Darren Chew <darren.chew@example.test>", "Late payment penalty",
     "Hello,\n\nI received a letter saying I owe a late payment fee of S$50 for the Certificate in Business Law. I paid on time via PayNow on 15 September. Could you look into this?\n\nThanks,\nDarren Chew", ("Darren Chew",)),
    ("H39", "Yvonne Tay <yvonne.tay@example.test>", "Laptop requirements",
     "Hi,\n\nWhat are the laptop requirements for the Professional Certificate in Game Design? Will a MacBook Air with Apple M2 work with Unity and Blender?\n\nThank you,\nYvonne Tay", ("Yvonne Tay",)),
    ("H40", "Muhammad Firdaus <firdaus.m@example.test>", "Attendance requirement",
     "Assalamualaikum and hello,\n\nWhat is the minimum attendance for the Advanced Diploma in Mechatronics to qualify for SkillsFuture funding? I may need to miss two sessions during Hari Raya Haji.\n\nThank you\nFirdaus", ("Firdaus",)),
)

HARD: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    ("X01", "Jessica Phua <jess.phua@example.test>", "Enquiry", "Hi,\n\nMy friend Wei Ling Tan took the Data Analytics course last year and recommended it. Is there a referral discount?\n\nThanks,\nJessica", ("Wei Ling Tan", "Jessica")),
    ("X02", "Grace Lim <grace.lim@example.test>", "Fees", "Hello,\n\nGrace here. How much is the Graduate Certificate in Infocomm Security? Please call me back.\n\nGrace", ("Grace",)),
    ("X03", "Rose Ng <rose.ng@example.test>", "Course dates", "Dear PaCE,\n\nWhen does the next run of Digital Marketing Analytics start?\n\nrose ng", ("rose ng",)),
    ("X04", "Ahmad <ahmad@example.test>", "Help", "hi can i apply for the ai course if i dont have a degree. thanks ahmad", ("ahmad",)),
    ("X05", "Melissa Koh <melissa.koh@example.test>", "On behalf of my son", "Dear Sir/Madam,\n\nI am writing on behalf of my son, Ethan Koh, who wants to take the Python Programming course during his school holidays. He is 17. Is that allowed?\n\nRegards,\nMelissa Koh", ("Ethan Koh", "Melissa Koh")),
    ("X06", "Jason Teo <jason.teo@example.test>", "Following up with Ms Chua", "Hi,\n\nI spoke to Ms Chua at the PaCE counter on Monday about transferring my credits. She said Mr Ravindran from Registry would email me but I have not heard back.\n\nThanks,\nJason", ("Ms Chua", "Mr Ravindran", "Jason")),
    ("X07", "Will Tan <will.tan@example.test>", "Exam", "Hi,\n\nWill the exam for Corporate Finance be open book?\n\nRegards,\nWill Tan", ("Will Tan",)),
    ("X08", "May Chen <may.chen@example.test>", "May intake", "Dear PaCE,\n\nIs there a May intake for the Certificate in Human Resource Management? If not, when is the next one?\n\nThank you,\nMay", (("May", 2),)),
    ("X09", "Lakshmi Narayanan <lakshmi.n@example.test>", "Certificate name correction", "Dear Registry,\n\nMy certificate shows my name as LAKSHMI NARAYAN but it should be LAKSHMI NARAYANAN. Can you reissue it?\n\nThank you,\nLakshmi Narayanan", ("LAKSHMI NARAYAN", "Lakshmi Narayanan")),
    ("X10", "Kenneth Yap <kenneth.yap@example.test>", "Course for my team", "Hello,\n\nOur director, Dr Angela Sim, asked me to find a leadership course for six managers. Please send details to Angela and me.\n\nKenneth Yap\nTraining Lead", ("Angela Sim", "Angela", "Kenneth Yap")),
    ("X11", "noreply <noreply@forms.example.test>", "New enquiry", "Full name: Tan Boon Huat\nContact number: 9345 6789\nEnquiry: Do you have weekend classes for the Diploma in Logistics?", ("Tan Boon Huat",)),
    ("X12", "Sarah Lee <sarah.lee@example.test>", "Payment", "Hi,\n\nI paid for the course on 3 Oct. Reference 88123. My colleague Hong Wei paid too, can you check both?\n\nSarah", ("Hong Wei", "Sarah")),
    ("X13", "Joel Lim <joel.lim@example.test>", "Question", "Dear PaCE Team,\n\nI am Joel, a final-year student at Temasek Polytechnic. Can I take the Professional Certificate in Robotics before I graduate?\n\nThank you\nJoel Lim", ("Joel", "Joel Lim")),
    ("X14", "Abdul Rahim bin Osman <rahim.o@example.test>", "Bursary", "Assalamualaikum,\n\nIs there a bursary for lower-income learners for the Certificate in Facilities Management?\n\nTerima kasih,\nAbdul Rahim bin Osman", ("Abdul Rahim bin Osman",)),
    ("X15", "Olivia Wang <olivia.wang@example.test>", "Thanks to Jun Jie", "Dear PaCE,\n\nPlease pass my thanks to Jun Jie at the front desk, he was very helpful. Also, is the Advanced Excel course still open for registration?\n\nOlivia", ("Jun Jie", "Olivia")),
    ("X16", "Tony Ho <tony.ho@example.test>", "Re: Registration", "Ok noted. Will the class be at Nanyang Executive Centre?\n\nTony", ("Tony",)),
    ("X17", "Priscilla Goh <p.goh@example.test>", "Recommendation letter", "Hi,\n\nFor the MSc application I need two referees. Can one of them be my supervisor at DBS Bank, Mr Desmond Lau, and the other my former lecturer Professor Siti Hajar?\n\nRegards,\nPriscilla", ("Desmond Lau", "Siti Hajar", "Priscilla")),
    ("X18", "Michelle Tan <michelle.tan@example.test>", "Class change", "Hi there,\n\nCan I move from Ms Lee's Tuesday class to Mr Wong's Thursday class for Business Writing?\n\nMichelle", ("Ms Lee", "Mr Wong", "Michelle")),
    ("X19", "Hiroshi Tanaka <h.tanaka@example.test>", "International applicant", "Dear Admissions,\n\nI am Hiroshi Tanaka from Osaka, Japan. Can I join the online Graduate Certificate in Supply Chain Analytics from overseas?\n\nBest regards,\nHiroshi", ("Hiroshi Tanaka", "Hiroshi")),
    ("X20", "Faith Chong <faith.chong@example.test>", "Refund", "Hello,\n\nI would like a refund for the Digital Photography workshop because it was cancelled.\n\nFaith Chong", ("Faith Chong",)),
    ("X21", "Admin LEO Pte Ltd <admin@leo.example.test>", "Corporate training", "Dear PaCE,\n\nLEO Engineering Pte Ltd would like to arrange a customised Workplace Safety course for 30 workers in December. Please contact our HR Executive Nadia Hassan.\n\nBest regards,\nAdmin Team", ("Nadia Hassan",)),
    ("X22", "Stephanie Wee <steph.wee@example.test>", "Prerequisite", "Hi,\n\nIs Calculus required for Quantitative Finance Foundations? I did A-level Mathematics at Raffles Junior College.\n\nThanks\nSteph", ("Steph",)),
    ("X23", "Ivan Chia <ivan.chia@example.test>", "Waiver", "Dear Sir/Madam,\n\nCan the application fee be waived for NTU alumni? I graduated with a BEng in 2015.\n\nYours sincerely,\nIvan Chia Wen Hao", ("Ivan Chia Wen Hao",)),
    ("X24", "Nicole Tay <nicole.tay@example.test>", "Course feedback", "Hi,\n\nI just finished Effective Presentation Skills with trainer Sunny Goh. It was excellent! Does Sunny teach any other courses?\n\nNicole", ("Sunny Goh", "Sunny", "Nicole")),
    ("X25", "Dennis Ong <dennis.ong@example.test>", "Course", "Dear PaCE,\n\nIs the Certificate in Interior Design Fundamentals suitable for beginners? I work in Sales at Courts Singapore.\n\nRegards,\nDennis", ("Dennis",)),
    ("X26", "Raj Kumar <raj.kumar@example.test>", "Address change", "Hello,\n\nPlease update my mailing address to Blk 123 Ang Mo Kio Ave 3, #05-67, Singapore 560123.\n\nRaj", ("Raj",)),
    ("X27", "Esther Lau <esther.lau@example.test>", "Wheelchair access", "Dear PaCE Team,\n\nMy mother Mrs Lau Siew Kim uses a wheelchair. Is the classroom at One-North accessible for her?\n\nThank you,\nEsther", ("Lau Siew Kim", "Esther")),
    ("X28", "Brandon Lee <brandon.lee@example.test>", "Course enquiry", "hello\n\ni want to ask if the cybersecurity course got night classes\n\nthanks\nbrandon", ("brandon",)),
    ("X29", "Cheryl Ang <cheryl.ang@example.test>", "Group Booking", "Hi PaCE,\n\nCould you hold four seats in the Design Thinking Masterclass for my team at Shopee Singapore? Names: Cheryl Ang, Marcus Lim, Fiona Toh and Darius Rahman.\n\nCheers,\nCheryl", ("Cheryl Ang", "Marcus Lim", "Fiona Toh", "Darius Rahman", "Cheryl")),
    ("X30", "Patrick O'Brien <p.obrien@example.test>", "Course timing", "Dear Sir or Madam,\n\nI am an expatriate working in Singapore. Are the Mandarin for Beginners classes in the evening?\n\nKind regards,\nPatrick O'Brien", ("Patrick O'Brien",)),
)


def _eml(sender: str, subject: str, body: str) -> bytes:
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, "PaCE General Enquiries <enquiries@pace-mock.example>", subject
    message["Message-ID"] = f"<{hashlib.sha256((sender + subject).encode()).hexdigest()[:24]}@example.test>"
    message.set_content(body)
    return bytes(message)


def dev_cases() -> list[tuple[str, dict, tuple[str, ...]]]:
    """(case_id, {raw_eml|graph_message}, names)."""
    cases = [(case_id, {"raw_eml": (MOCK_EML / f"{case_id}.eml").read_bytes()}, names) for case_id, names in MOCK_NAMES.items()]
    case_id, sender, subject, body, names = SIGNATURE_SAMPLE
    cases.append((case_id, {"raw_eml": _eml(sender, subject, body)}, names))
    cases.append(("sample-graph-followup", {"graph_message": GRAPH_SAMPLE}, ("Jun Hao", "Mei Xuan Koh")))
    cases.append(("example-scholarship", {"raw_eml": (EXAMPLES / "scholarship.eml").read_bytes()}, ("Tan Mei Ling",)))
    cases.append(("example-graph", {"graph_message": json.loads((EXAMPLES / "graph_message.json").read_text())}, ("Tan Mei Ling",)))
    return cases


def held_out_cases() -> list[tuple[str, dict, tuple[str, ...]]]:
    return [(case_id, {"raw_eml": _eml(sender, subject, body)}, names) for case_id, sender, subject, body, names in HELD_OUT]


def hard_cases() -> list[tuple[str, dict, tuple[str, ...]]]:
    return [(case_id, {"raw_eml": _eml(sender, subject, body)}, names) for case_id, sender, subject, body, names in HARD]
