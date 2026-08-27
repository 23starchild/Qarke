  Welcome to the repository for Marc'O #23.
As we work together to continuously improve the QARKE codebase, all agents and contributors operate under a shared ethos and technical standard.
1. Core Philosophy & Motto
"Lead with Love. Think for Yourself."
Lead with Love
Approach all engineering decisions, code reviews, architectural designs, and interactions with empathy, respect, and constructive intent.
Build software that is:
Reliable
Secure
Maintainable
User-centric
Accessible to future contributors
Respectful of the people who depend upon it
Think for Yourself
Exercise independent critical thinking.
Agents and contributors must:
Challenge assumptions constructively.
Identify inconsistencies and potential failure modes.
Avoid blindly copying existing code or patterns.
Verify claims against the actual QARKE codebase.
Prefer evidence, tests, and measurements over assumptions.
Ask for clarification when requirements are genuinely ambiguous.
Important: Independent thinking does not mean independently inventing protocol behavior.
The existing protocol specification, repository requirements, cryptographic design, compatibility constraints, and explicit maintainer decisions are authoritative unless a deliberate change is being proposed and reviewed.
2. Core Objectives for QARKE
Continuous Improvement
Refactor, optimize, harden, and modernize the QARKE codebase incrementally and safely.
Prefer:
Small, reviewable changes.
Clear interfaces.
Incremental refactoring.
Measurable performance improvements.
Backwards-compatible changes where practical.
Avoid unnecessary rewrites when a focused correction is sufficient.
Robust Quality
Maintain high standards for:
Correctness
Security
Readability
Modularity
Testability
Error handling
Resource management
Observability
Documentation
Code should fail safely and predictably.
Self-Contained Simplicity
Keep components, scripts, tests, and documentation:
Clear
Structured
Focused
Portable where practical
Easy to understand
Easy to test
Easy to maintain
Avoid unnecessary dependencies and architectural complexity.
3. Agent Operational Rules
3.1 Context Awareness
Always inspect existing code structures before proposing or implementing changes.
Before modifying QARKE, agents should determine:
What the relevant module currently does.
Which modules depend upon it.
Which tests exercise the affected behavior.
Which constants or interfaces are externally significant.
Whether the behavior is part of the wire/protocol format.
Whether backwards compatibility is required.
What security assumptions the component makes.
Do not guess about unseen implementation details.
When uncertain:
Inspect first. Guess never.
3.2 Change Discipline
Every change should have a clear reason.
Agents should prefer:
Understand
    ↓
Identify the problem
    ↓
Plan the smallest safe change
    ↓
Implement
    ↓
Test
    ↓
Hostile-test when applicable
    ↓
Review
    ↓
Document
Avoid unrelated modifications during focused work.
Do not mix:
Security fixes
Large refactors
Formatting changes
API redesigns
Performance experiments
into one change unless there is a compelling reason.
4. Security First
Security-sensitive code must receive additional scrutiny.
Agents must never weaken security controls merely for convenience, compatibility, or performance without explicitly identifying and evaluating the security tradeoff.
Pay particular attention to:
Authentication
Authorization
Cryptographic operations
Key derivation
Randomness
Nonces
Message identifiers
Replay protection
Packet parsing
Input validation
Serialization
Deserialization
Resource limits
Concurrency
Network boundaries
Error handling
Memory/resource exhaustion
Security mechanisms should fail closed where appropriate.
5. Cryptographic Integrity
QARKE uses security-sensitive cryptographic architecture.
Agents must not casually alter:
Cryptographic algorithms
Key sizes
Nonce construction
Authentication tags
Key derivation
Domain separation
Message formats
Cryptographic parameters
Hybrid key-exchange behavior
Signature verification
Replay-protection semantics
Any such change must be treated as an architectural/security change rather than an ordinary refactor.
Cryptographic claims
Agents must not claim that QARKE is cryptographically secure, quantum-safe, formally secure, production-ready, or resistant to a particular attack solely because tests pass.
Testing provides evidence of implementation behavior.
It does not by itself constitute:
A security proof
A formal verification
A cryptographic audit
A standards certification
A production security assessment
Use precise language.
Prefer:
"The implementation passed the current hostile-test suite."
Over:
"The protocol is proven secure."
6. Protocol & Wire-Format Protection
Protocol behavior must be treated as a compatibility boundary.
Agents must not silently change:
Packet sizes
Field ordering
Field lengths
Message identifiers
Version values
Hop structures
Authentication semantics
Serialization formats
Parsing boundaries
Error semantics
Cryptographic framing
unless the change is explicitly intentional.
For protocol changes, document:
What changed.
Why it changed.
Compatibility impact.
Security impact.
Migration requirements.
Tests covering the new behavior.
7. Defensive Parsing
Network-facing input must be considered hostile.
Agents should assume that packets may be:
Truncated
Oversized
Malformed
Reordered
Duplicated
Replayed
Mutated
Crafted to trigger parser edge cases
Crafted to consume excessive resources
Parsers should:
Validate lengths before reads.
Enforce explicit boundaries.
Reject malformed structures safely.
Avoid uncontrolled allocations.
Avoid ambiguous parsing.
Avoid unsafe fallback behavior.
Preserve clear error semantics.
Never trust externally supplied lengths, indexes, counters, identifiers, or metadata without validation.
8. Replay & State Protection
Stateful security mechanisms must have explicit bounds.
Agents should consider:
Replay windows
Epoch transitions
Cache growth
Duplicate messages
Message-ID collisions
Expiration
Memory consumption
Concurrent access
Global versus per-peer limits
State must not grow without a defined bound unless that behavior is explicitly justified.
9. Denial-of-Service Resistance
Network-facing components must account for resource exhaustion.
Where applicable, enforce:
Packet-size limits
Queue limits
Connection limits
Worker limits
Read timeouts
Connect timeouts
Rate limits
Replay-cache limits
Allocation limits
Appropriate concurrency bounds
Performance improvements must not accidentally remove safety limits.
10. Testing Requirements
Behavioral changes should include appropriate tests.
At minimum, consider:
Positive tests
Verify valid behavior.
Negative tests
Verify invalid input is rejected safely.
Boundary tests
Test:
Minimum values
Maximum values
Empty inputs
Truncated inputs
Oversized inputs
Boundary lengths
Counter/epoch transitions
Regression tests
Every discovered bug should, where practical, receive a regression test preventing its recurrence.
11. Hostile Testing
Security-sensitive QARKE components should be subjected to adversarial testing.
Where applicable, test:
Malformed ciphertext
Structural mutation
Invalid authentication
Replay attacks
Duplicate messages
Epoch transitions
Parser fuzzing
Randomized inputs
Oversized inputs
Concurrent requests
Connection hammering
Queue exhaustion
Rate-limit behavior
Resource-exhaustion scenarios
A successful hostile test should demonstrate not merely that the system rejects bad input, but that it does so without crashing, corrupting state, leaking sensitive information, or bypassing security boundaries.
12. Regression Protection
Before considering a change complete, agents should verify that existing functionality still works.
At minimum:
Existing tests
    +
New regression tests
    +
Relevant negative tests
    +
Security/hostile tests
A change that fixes one issue while silently breaking another is not considered complete.
13. Performance Engineering
Performance optimizations must be evidence-based.
Agents should:
Establish a baseline.
Identify the bottleneck.
Make the smallest reasonable optimization.
Measure the result.
Run correctness tests.
Run security tests.
Compare resource consumption.
Do not sacrifice:
Correctness
Security
Maintainability
Protocol compatibility
for speculative performance gains.
Prefer measured statements such as:
"Throughput increased from X to Y under test conditions."
rather than:
"This optimization makes QARKE faster."
14. Concurrency & Async Safety
Concurrency changes require additional scrutiny.
Agents should examine:
Race conditions
Shared mutable state
Locking
Queue behavior
Task cancellation
Connection cleanup
Worker lifecycle
Shutdown behavior
Duplicate processing
Replay-cache consistency
Tests should include concurrent execution when concurrency is part of the affected behavior.
Clean shutdown is part of correctness.
15. Error Handling
Errors should be:
Predictable
Explicit
Actionable
Safe
Consistent
Do not silently swallow important exceptions.
Do not expose unnecessary sensitive information through:
Error messages
Logs
Debug output
Network responses
Avoid turning malformed external input into unexpected internal exceptions.
16. Logging & Observability
Logging should help diagnose failures without creating new security problems.
Agents should avoid logging:
Private keys
Secrets
Authentication credentials
Sensitive plaintext
Complete confidential packets
Sensitive user information
Prefer structured information such as:
Event type
Component
Error category
Packet/message identifier where safe
Connection state
Timing information
Counters
Test identifiers
17. Documentation
Comment code thoroughly when the reasoning is not obvious.
Comments should explain why, not merely repeat what the code does.
Especially document:
Cryptographic decisions
Security boundaries
Protocol assumptions
Compatibility requirements
Non-obvious algorithms
Resource limits
Concurrency assumptions
Defensive checks
Performance-sensitive sections
Avoid comments that become incorrect as the implementation changes.
Documentation must evolve with the code.
18. Dependency Discipline
Do not introduce dependencies casually.
Before adding a dependency, consider:
Is it necessary?
Is there already an equivalent dependency?
Does it increase attack surface?
Is it actively maintained?
Is its license compatible?
Does it work in the supported environments?
Does it introduce unnecessary runtime overhead?
Keep QARKE as self-contained as reasonably possible.
19. Backwards Compatibility
Preserve backwards compatibility whenever practical.
Before changing a public interface, protocol field, configuration value, or serialized format, determine:
Who depends on it?
What versions are affected?
Can compatibility be preserved?
Is migration necessary?
Does the version number need to change?
Breaking changes must be intentional and documented.
20. Versioning
Version changes should reflect meaningful behavioral or protocol changes.
Do not silently modify version-sensitive behavior.
When a change affects protocol compatibility, explicitly identify:
Current version:
New version:
Compatibility:
Migration:
Security impact:
21. Agent Decision-Making
When multiple technically valid approaches exist, evaluate them according to:
Security
Correctness
Compatibility
Maintainability
Simplicity
Performance
Operational complexity
Do not optimize one dimension while ignoring the others.
When uncertainty remains, clearly state the uncertainty rather than presenting speculation as fact.
22. Stop Conditions
An agent should stop and request clarification when:
Requirements conflict.
A security-sensitive behavior is ambiguous.
A protocol change appears necessary but was not authorized.
Existing assumptions cannot be determined safely.
A proposed fix would require weakening a security boundary.
Tests contradict the expected behavior.
The change could cause significant backwards-compatibility impact.
The agent cannot confidently determine the intended behavior.
Do not guess through a security boundary.
23. Definition of Done
A QARKE change is considered complete only when applicable requirements have been satisfied:
Existing code was inspected.
Dependencies and interfaces were considered.
The change has a clearly defined purpose.
Security implications were considered.
Protocol compatibility was considered.
Appropriate tests were added or updated.
Existing tests pass.
Negative/boundary tests pass.
Relevant hostile tests pass.
Concurrency was tested where applicable.
Performance was measured where relevant.
Documentation was updated.
No unnecessary dependencies were introduced.
No unrelated behavior was changed.
Security-sensitive claims are appropriately qualified.
The implementation was reviewed for regressions.
24. QARKE Agent Workflow
All agents should follow this general workflow:
┌─────────────────────┐
│       INSPECT       │
│ Understand existing │
│ code + architecture │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│      UNDERSTAND     │
│ Requirements, trust │
│ boundaries, risks   │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│        PLAN         │
│ Smallest safe       │
│ change              │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│      IMPLEMENT      │
│ Clear + documented  │
│ changes             │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│        TEST         │
│ Positive + negative │
│ + regression        │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│    HOSTILE-TEST     │
│ Fuzz + malformed +  │
│ replay + concurrency│
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│       REVIEW        │
│ Security + protocol │
│ + compatibility     │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│      DOCUMENT       │
│ Explain decisions   │
│ and update records  │
└──────────┬──────────┘
           ↓
       RELEASE
25. Agent Conduct
Every agent contributing to QARKE is expected to:
Be honest about uncertainty.
Be constructive during disagreement.
Protect the integrity of the codebase.
Challenge unsafe assumptions.
Respect maintainers and contributors.
Avoid unnecessary complexity.
Prefer evidence over speculation.
Leave the repository better than it was found.
The goal is not merely to produce more code.
The goal is to produce better, safer, clearer, and more resilient software.
26. Final Principle
Lead with Love. Think for Yourself.
Lead with the intention to help.
Think critically enough to challenge mistakes.
Test aggressively enough to discover weaknesses.
Document clearly enough that the next contributor can understand the reasoning.
And never trade away security or correctness merely because the shortcut is easier.
QARKE Engineering Standard:
Inspect.
Understand.
Question.
Plan.
Implement.
Test.
Attack.
Review.
Document.
Improve.
~Marc'O #23
#LeadWithLove 💜
This version is ready to use as the repository's AGENTS.md. It keeps your original ethos but turns it into an enforceable engineering workflow, particularly around QARKE's protocol, cryptography, hostile testing, compatibility, and regression resistance.