"""
Phishing Email Detection & Awareness Dashboard
Module: Synthetic Email Dataset Generator
File: data/generate_dataset.py

Generates a balanced, realistic, and fully safe synthetic dataset of 600+ email records
for training, testing, and calibrating defensive email analysis models.
All domains and IP addresses adhere to RFC 2606 (.test, example.com, example.org)
and RFC 5737 (TEST-NET documentation IP blocks: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""

import os
import csv
import random

def generate_dataset(output_path="data/phishing_email_dataset.csv", num_samples=600):
    random.seed(42)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Legitimate email components
    legit_senders = [
        ("registrar@university.example.edu", "university.example.edu"),
        ("hr-announcements@workplace.example.org", "workplace.example.org"),
        ("project-lead@team.example.com", "team.example.com"),
        ("calendar-service@internal.example.org", "internal.example.org"),
        ("order-support@eshop.example.com", "eshop.example.com"),
        ("monthly-digest@techreview.example.org", "techreview.example.org"),
        ("security-team@corp.example.com", "corp.example.com"),
        ("notifications@fictional-bank.example.com", "fictional-bank.example.com"),
        ("library-services@campus.example.edu", "campus.example.edu"),
        ("devops-alerts@infra.example.org", "infra.example.org"),
    ]

    legit_templates = [
        (
            "Quarterly Academic Schedule Announcement",
            "Dear Student, the updated timetable for the upcoming semester is now published on the official campus portal. Please review your enrolled courses and lecture hall locations prior to next Monday. No action is required if your schedule is finalized.",
            "https://campus.example.edu/schedule",
            "academic_calendar_2026.pdf"
        ),
        (
            "Upcoming Scheduled Maintenance Notice",
            "Hello Team, please be advised that routine infrastructure maintenance is scheduled for Saturday between 02:00 UTC and 04:00 UTC. Network services may experience brief latency. Thank you for your cooperation.",
            "https://infra.example.org/status",
            ""
        ),
        (
            "HR Policy Update: Annual Benefits Enrollment",
            "Dear Colleague, open enrollment for health and wellness benefits will commence on the first of next month. You may review current plan details and provider directories at your convenience on the intranet benefits hub.",
            "https://workplace.example.org/intranet/benefits",
            "benefits_guide_summary.pdf"
        ),
        (
            "Project Sprint Planning Meeting Notes",
            "Hi everyone, thanks for attending today's sprint retrospective. The action items and backlog items have been updated in the project tracker. Our next standup will take place Wednesday at 10:00 AM.",
            "https://team.example.com/projects/sprint-42",
            "sprint_notes.docx"
        ),
        (
            "Your Order #49281 Confirmation",
            "Thank you for your recent purchase at E-Shop. Your order has been processed and will dispatch within two business days. You can view your order status and shipping history inside your personal dashboard.",
            "https://eshop.example.com/orders/49281",
            "order_receipt_49281.pdf"
        ),
        (
            "Tech Digest: Industry Cybersecurity Trends",
            "Welcome to this week's issue of the Engineering & Security Digest. This week we discuss defensive coding practices, zero-trust architectures, and upcoming open-source conferences. Enjoy the read!",
            "https://techreview.example.org/digest/issue-104",
            ""
        ),
        (
            "Security Notice: Successful Password Update",
            "Hello, this notification confirms that your account password was successfully updated today from an authorized device. If you initiated this change, no further action is necessary. If you did not, please contact your internal helpdesk directly.",
            "https://corp.example.com/security/activity",
            ""
        ),
        (
            "Monthly Account Statement Available",
            "Dear Customer, your monthly e-statement for account ending in 4102 is now ready for viewing. To access your statement safely, log in to your mobile app or visit our official website directly. We will never ask for your PIN via email.",
            "https://fictional-bank.example.com/accounts/statements",
            "statement_summary_october.pdf"
        ),
        (
            "Library Book Return Reminder",
            "Greetings, this is a polite reminder that your borrowed textbook 'Computer Networking: Principles' is due for return by Friday afternoon. You can renew your loan online if no reservations are pending.",
            "https://campus.example.edu/library/loans",
            ""
        ),
        (
            "Team Lunch and Milestone Celebration",
            "Hello everyone, to celebrate completing Phase 1 of our software deliverables, the department is hosting a catered lunch this Thursday at 12:30 PM in the 4th floor lounge. We hope to see everyone there!",
            "",
            ""
        )
    ]

    # Synthetic Phishing email components
    phish_senders = [
        ("security-alert@account-check.invalid.test", "account-check.invalid.test"),
        ("billing-support@paypal-secure-portal.invalid.test", "paypal-secure-portal.invalid.test"),
        ("service@bank-verification-center.invalid.test", "bank-verification-center.invalid.test"),
        ("it-support@global-helpdesk-urgent.invalid.test", "global-helpdesk-urgent.invalid.test"),
        ("rewards@gift-claim-center.invalid.test", "gift-claim-center.invalid.test"),
        ("delivery-update@fedx-tracking-parcel.invalid.test", "fedx-tracking-parcel.invalid.test"),
        ("hr-payroll@salary-adjustment-auth.invalid.test", "salary-adjustment-auth.invalid.test"),
        ("admin@exec-board-internal.invalid.test", "exec-board-internal.invalid.test"),
        ("alert@microsoft-365-security-notice.invalid.test", "microsoft-365-security-notice.invalid.test"),
        ("accountant@cloud-invoice-system.invalid.test", "cloud-invoice-system.invalid.test"),
    ]

    phish_templates = [
        (
            "URGENT: Verify Your Account Immediately to Avoid Suspension",
            "Dear Valued Customer, We have detected unauthorized login attempts from an unknown device. Your account will be permanently deactivated within 24 hours unless you verify your password and identity immediately. Click the secure link below to confirm your credentials right now.",
            "http://198.51.100.10/verify-account?user=target",
            ""
        ),
        (
            "Action Required: Outstanding Invoice #INV-9902 Payment Overdue",
            "ATTENTION: Your account has an overdue balance of $4,850.00. Immediate settlement is required to prevent legal escalation and service termination. Please download the attached invoice ledger immediately and execute the wire instructions.",
            "http://203.0.113.45/invoices/download",
            "invoice_overdue_statement.pdf.exe"
        ),
        (
            "CONGRATULATIONS: You Have Won a $1,000 Amazon Gift Card!",
            "Dear User, You have been randomly selected as our grand prize recipient in today's customer appreciation raffle! Claim your reward now before the allocation window expires in 30 minutes. Enter your credit card details for 100% free delivery verification.",
            "http://bit.ly.safe-mock.invalid.test/gift-claim-now",
            ""
        ),
        (
            "Critical Notice: Your Mailbox Password Expires in 2 Hours",
            "Dear User, Your corporate email password is set to expire today. Failure to update credentials will result in immediate termination of mail server access. Keep your existing password by validating your account at the following secure portal:",
            "http://192.0.2.88/portal/auth-reset",
            "password_reset_form.html"
        ),
        (
            "Delivery Failure: Package #US-98214-DEL Holds Status Urgent",
            "Dear Client, Our courier was unable to deliver your priority package due to an incomplete delivery address and unpaid customs surcharge fee of $2.95. Click here to confirm personal details and make payment immediately to avoid package return.",
            "http://tracking-courier-express.invalid.test/pay-surcharge",
            ""
        ),
        (
            "HR Confidential: Immediate Mandatory Salary Adjustment Confirmation",
            "Dear Employee, Human Resources has rolled out an unscheduled salary adjustment for all active staff. Review your updated salary tier by opening the encrypted spreadsheet attached below using your Windows domain credentials.",
            "",
            "salary_bonus_schedule.xlsx.vbs"
        ),
        (
            "Executive Request: Urgent Wire Transfer Task - Confidential",
            "Are you currently at your desk? I am in a board meeting and need you to process an emergency confidential vendor wire transfer before market close. Reply immediately so I can provide the routing details. Do not contact me by phone as I am unavailable.",
            "",
            ""
        ),
        (
            "Security Alert: Multiple Failed Login Attempts on Office 365",
            "URGENT NOTICE: A foreign IP address in Moscow attempted to access your cloud mailbox. To protect your sensitive files, sign in to your Microsoft account immediately via the emergency link below to block unauthorized users.",
            "http://198.51.100.99/login.microsoftonline.portal-auth.invalid.test",
            ""
        ),
        (
            "Payment Notification: Tax Refund Available - Claim Immediately",
            "Official Notice: You are eligible to receive an unexpected federal tax refund of $842.10. To release your fund deposit, fill out the attached electronic form with your Social Security Number, bank account number, and date of birth.",
            "http://gov-refund-tax-claim.invalid.test/form",
            "tax_refund_claim_sheet.scr"
        ),
        (
            "Suspicious Activity Warning: Debit Card Temporarily Locked",
            "Security Department Alert: Suspicious debit transactions were flagged on your card. For your security, your card is locked. Click here immediately to confirm your card number, CVV, and billing address to restore privileges.",
            "http://203.0.113.120/bank/card-unlock",
            ""
        )
    ]

    records = []
    half_samples = num_samples // 2

    # Generate Legitimate records
    for i in range(1, half_samples + 1):
        sender_email, domain = random.choice(legit_senders)
        subj, body, url, att = random.choice(legit_templates)
        
        # Add slight natural variations
        variations = [
            "",
            " Best regards, Support Team.",
            " Please reach out if you have any questions.",
            " Reference Ticket: #" + str(random.randint(10000, 99999)) + ".",
            " System status is normal."
        ]
        var_body = body + random.choice(variations)
        var_subj = subj + (f" (Ref #{random.randint(100, 999)})" if random.random() > 0.6 else "")

        records.append({
            "email_id": f"EML-LEGIT-{i:04d}",
            "sender": sender_email,
            "sender_domain": domain,
            "subject": var_subj,
            "body": var_body,
            "urls": url,
            "attachment_name": att,
            "label": "LEGITIMATE"
        })

    # Generate Phishing records
    for i in range(1, half_samples + 1):
        sender_email, domain = random.choice(phish_senders)
        subj, body, url, att = random.choice(phish_templates)
        
        # Add synthetic phishing urgency variations
        urgency_suffixes = [
            " ACT NOW TO PREVENT ACCOUNT CLOSURE.",
            " Final notice: response required within 15 minutes.",
            " Failure to comply will lead to legal action.",
            " Your access will be terminated indefinitely.",
            " Immediate verification required."
        ]
        var_body = body + (random.choice(urgency_suffixes) if random.random() > 0.4 else "")
        var_subj = subj if random.random() > 0.3 else "[ACTION REQUIRED] " + subj

        records.append({
            "email_id": f"EML-PHISH-{i:04d}",
            "sender": sender_email,
            "sender_domain": domain,
            "subject": var_subj,
            "body": var_body,
            "urls": url,
            "attachment_name": att,
            "label": "PHISHING"
        })

    # Shuffle the dataset so labels are mixed
    random.shuffle(records)

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "email_id", "sender", "sender_domain", "subject", 
            "body", "urls", "attachment_name", "label"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Successfully generated {len(records)} synthetic email records at: {output_path}")
    print(f"    - Legitimate samples: {half_samples}")
    print(f"    - Phishing samples: {half_samples}")
    return len(records)

if __name__ == "__main__":
    generate_dataset()
