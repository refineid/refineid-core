# STPA: how this project analyses hazards

STPA (System-Theoretic Process Analysis) is the hazard analysis every
RefineID design goes through. This file explains the method and how the
project uses it. The analyses themselves are elsewhere:
[security/stpa-rapp.md](security/stpa-rapp.md) is the record for RAPP and
the applications that use it, and a platform repository may keep its own
for platform-only parts.

## What STPA is

Most hazard analyses ask which part can fail. STPA asks how the system can
be controlled unsafely, even when no part fails. It treats safety as a
control problem: a loss happens when a controller (a person, an app, an
operating system, a protocol peer) issues a control action that is unsafe
in the situation, or fails to issue one that is needed. The usual cause is
not a broken part but a controller acting on a wrong picture of the
system, because feedback was missing, late or misleading.

STPA comes from STAMP (System-Theoretic Accident Model and Processes),
Nancy Leveson's accident model, and is described in full in the references
below. It finds the problems a list of failures or threats misses:
components that each work as specified but interact badly, requirements
that are wrong, and people or programs that do the wrong thing because
they were told the wrong thing.

## The steps

The STPA Handbook describes four steps.

1. **Define the purpose of the analysis.** Name the losses a real
   stakeholder could suffer (L-1, L-2, ...): for example a card operation
   without the holder's consent, or a holder who cannot log in and cannot
   tell why. Name the hazards (H-1, H-2, ...): system states that, together
   with a worst-case environment, lead to a loss. Turn each hazard around
   into a system-level constraint: what the system must never do or must
   always do.
2. **Model the control structure.** Draw the controllers, the control
   actions each one issues, the feedback each one gets, and what lies
   between them: the actuators that carry out an action, the sensors that
   report back, and the controlled process itself. Look first for
   missing, late or misleading feedback.
3. **Identify unsafe control actions (UCA-1, ...).** For each control
   action, ask in which context it is unsafe when it is:
   - not provided when needed (N);
   - provided when it leads to a hazard (P);
   - provided too early, too late or in the wrong order (T);
   - stopped too soon or applied too long (D).
4. **Identify loss scenarios.** For each unsafe control action, find two
   kinds of scenario:
   - why the controller would issue it, or fail to issue a needed one:
     what it believed, which feedback misled it, which timing or
     interaction allowed it;
   - why a safe control action would still not be carried out, or be
     carried out wrongly: an actuator, the controlled process or a
     feedback path that fails or misbehaves.

From these come the **controller constraints (CC-1, ...)**: what the
design enforces to prevent or mitigate each unsafe control action, each
naming the ones it closes, and further requirements from the loss
scenarios.

## How this project uses it

- **Every design has an STPA, sized to the change.** A small change
  states its analysis in the pull request. A change to the control
  structure updates the record. A change with no control action or
  feedback to analyse says so in one line.
- **Real losses and hazards only.** Add a loss only when a real
  stakeholder could suffer it, and a hazard only for a real system state
  that leads to one. Do not invent threats to fill the method. A few real
  ones beat a long list.
- **One numbering.** Identifiers continue across the whole record and are
  never reused. A section adds the next free numbers.
- **The record states what holds.** A new constraint that replaces an
  older one says so ("supersedes CC-41's idle limit"), so a reader can
  find which rule is in force.
- **Security is part of it.** An attacker is one more source of unsafe
  control actions and misleading feedback, analysed in the same structure
  (Young and Leveson 2014).

## References

- Nancy G. Leveson. *Engineering a Safer World: Systems Thinking Applied
  to Safety.* MIT Press, 2011. ISBN 978-0-262-01662-9. Open access:
  <https://doi.org/10.7551/mitpress/8179.001.0001>. The method's
  foundation: STAMP, STPA and the reasoning behind them.
- Nancy G. Leveson and John P. Thomas. *STPA Handbook.* MIT, March 2018.
  Free for non-commercial use from <http://mit.edu/psas>. The practical
  guide: steps, tables and worked examples.
- Nancy G. Leveson. "A new accident model for engineering safer systems."
  *Safety Science* 42(4), 2004, pp. 237–270.
  <https://doi.org/10.1016/S0925-7535(03)00047-X>. The paper that
  introduced STAMP.
- John P. Thomas. *Extending and automating a systems-theoretic hazard
  analysis for requirements generation and analysis.* PhD thesis, MIT,
  2013. <https://dspace.mit.edu/handle/1721.1/81055>. How to find unsafe
  control actions systematically from their context.
- William Young and Nancy G. Leveson. "An integrated approach to safety
  and security based on systems theory." *Communications of the ACM*
  57(2), 2014, pp. 31–35. <https://doi.org/10.1145/2556938>. Applying the
  same analysis to security.
