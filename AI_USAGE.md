# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used ChatGPT to help implement the functions in tmcheck/core.py and the CLI in tmcheck/__main__.py, and review the STRIDE applicability rules.I also used it to identify missing threats in the Rawaj Pay model and organize the final verification steps. I used the provided pytest suite and ran the CLI locally to check the implementation and inspect the model's results. I reviewed the suggestions and checked them against the assignment requirements rather than assuming they were automatically correct.

## What AI got wrong

The AI initially focused on implementing the Python checker and passing the public tests, but that did not mean the entire assignment was complete. When I ran the CLI against models/rawaj_scoring.yaml, it still reported 11 coverage gaps and two policy findings. I checked the assignment instructions and confirmed that completing the YAML threat model was also a separate requirement. This taught me to verify both the implementation and the model output instead of relying only on passing tests.

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
   
   A data store cannot be impersonated like a user or process, so Spoofing does not apply to it directly. Instead, Spoofing threats apply to the external entity or process that accesses the store.

2. Which of your eleven new threats would you fix first, and why that one?
   
   I would fix T33 first because unauthorized changes to case data could corrupt evidence and lead to incorrect decisions.
