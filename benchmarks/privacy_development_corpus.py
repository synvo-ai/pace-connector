"""Adversarial development probes; intentionally disjoint from final held-out.

This module is not imported by the runtime or the final qualification runner.
It records the independent-review reproductions used while defining the
residual-sentinel scope, so they cannot become hidden production allowlists.
"""

DEVELOPMENT_PERSON_PROBES = (
    "Li Kai", "Ng Yu", "Ho Yi", "José García", "María Cruz", "Élodie Martin",
    "François Dubois", "Zoë Smith", "Łukasz Kowalski", "Søren Nielsen",
    "Nguyễn An", "Müller Anna", "Jane Doe", "jane doe", "J. Doe",
    "Maria-Louise Tan", "O'NEILL CLARA",
)

DEVELOPMENT_BUSINESS_PROBES = (
    "Programme Details", "Programme Enquiry", "Payment Receipt", "Course Schedule",
    "Application Form", "Programme Information", "Payment Status", "General Enquiry",
    "Training Allowance", "Professional Certificate", "Data Analytics Programme",
    "Intake Status", "Fee Payment", "Student Services", "Programme Office",
    "Payment Confirmation", "Receipt Attached", "Dear Team", "Best Regards",
)

DEVELOPMENT_STRUCTURAL_PROBES = (
    "SYN-ABC-123 asks about intake", "Application: APP 2026 001",
    "Reference REF CASE 001", "+65 8 1 2 3 4 5 6 7", "S 1 2 3 4 5 6 7 A",
)
