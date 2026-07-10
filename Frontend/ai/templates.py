from .base import Explanation

# Pre-defined deterministic templates for clean fallback operations
CATEGORY_TEMPLATES = {
    "security": Explanation(
        explanation=(
            "The static code analysis flagged a potential security risk in the codebase. "
            "This generally arises from trusting user-controlled inputs, loading obsolete packages, "
            "or invoking system utilities via subprocess commands without sanitization."
        ),
        why_it_matters=(
            "Security vulnerabilities expose the server and user database to unauthorized manipulation, "
            "allowing external actors to read, write, or destroy sensitive state assets."
        ),
        possible_impact=(
            "Potential Remote Code Execution (RCE), database compromise via SQL Injection (SQLi), "
            "Client session hijacking through Cross-Site Scripting (XSS), or denial of service."
        ),
        recommended_fix=(
            "Use parameterized inputs, sanitize and escape all user variables, avoid direct shell "
            "invocations, and pin dependency requirements to patched versions."
        ),
        developer_friendly_summary="Security alert: Vulnerable patterns or packages detected in source."
    ),
    "bugs": Explanation(
        explanation=(
            "The code contains logical defects, syntax anomalies, or import warnings. "
            "Examples include undefined variables, references to empty pointers, or unused imports."
        ),
        why_it_matters=(
            "Unresolved bugs directly affect runtime reliability, causing execution failures "
            "or unexpected exceptions in production."
        ),
        possible_impact=(
            "Unhandled exceptions, application loop locks, unexpected null outputs, "
            "or server runtime crashes."
        ),
        recommended_fix=(
            "Verify all variable allocations, resolve unused references, catch potential exceptions, "
            "and compile code models locally before commits."
        ),
        developer_friendly_summary="Logic/Bug Warning: High likelihood of runtime execution failure."
    ),
    "codeSmells": Explanation(
        explanation=(
            "The code structure violates clean code design practices, displays high cyclomatic complexity, "
            "or implements known python anti-patterns (such as cyclomatic structures)."
        ),
        why_it_matters=(
            "Code smells indicate high technical debt. Over-convoluted files are hard to understand, "
            "maintain, and verify with standard unit tests."
        ),
        possible_impact=(
            "Low code maintainability, increased occurrence of regression defects during refactoring, "
            "and slower feature implementation."
        ),
        recommended_fix=(
            "Refactor code logic: divide complex functions, replace nested conditions with guards, "
            "and eliminate unused helper blocks."
        ),
        developer_friendly_summary="Code Smell: Code is over-complex or violates clean design standards."
    ),
    "performance": Explanation(
        explanation=(
            "An inefficient coding style or suboptimal logic flow (like redundant loops "
            "or repetitive database selections) has been identified."
        ),
        why_it_matters=(
            "サブoptimal loops and database accesses lead to increased processor load, latency issues, "
            "and poor resource scaling."
        ),
        possible_impact=(
            "Degraded response times, excessive memory consumption, or server latency."
        ),
        recommended_fix=(
            "Use bulk queries, cache recurring computation values, select dictionary indexes over "
            "nested arrays, and optimize database indexing."
        ),
        developer_friendly_summary="Performance Warning: Suboptimal code logic affecting scaling capabilities."
    )
}

RULE_TEMPLATES = {
    "RADON": Explanation(
        explanation=(
            "This function cyclomatic complexity ranks C or worse. It contains too many logical "
            "branches (if-statements, loops, or returns), making code logic hard to trace."
        ),
        why_it_matters=(
            "Functions with excessive branch pathways are difficult to cover with unit tests. "
            "A developer modifying this block is highly likely to introduce regression bugs."
        ),
        possible_impact=(
            "High maintenance overhead, testing difficulties, and high probability of regression failures."
        ),
        recommended_fix=(
            "Decompose the function logic. Extract the inner branches or conditions into smaller, "
            "single-responsibility helper functions."
        ),
        developer_friendly_summary="Complexity issue: Control flow branches are too complex (Rank C+)."
    )
}

def get_fallback_explanation(category: str, rule_id: str, title: str, description: str) -> Explanation:
    """Returns a pre-structured Explanation based on rule_id or category."""
    # Check rule prefix first
    for rule_prefix, templ in RULE_TEMPLATES.items():
        if str(rule_id).startswith(rule_prefix):
            return Explanation(
                explanation=f"{templ.explanation} (Issue: {title})",
                why_it_matters=templ.why_it_matters,
                possible_impact=templ.possible_impact,
                recommended_fix=templ.recommended_fix,
                developer_friendly_summary=templ.developer_friendly_summary
            )
            
    # Default category fallback
    cat = str(category).lower()
    default_templ = CATEGORY_TEMPLATES.get(cat, CATEGORY_TEMPLATES["codeSmells"])
    
    return Explanation(
        explanation=f"{default_templ.explanation} ({title}: {description})",
        why_it_matters=default_templ.why_it_matters,
        possible_impact=default_templ.possible_impact,
        recommended_fix=default_templ.recommended_fix,
        developer_friendly_summary=default_templ.developer_friendly_summary
    )
