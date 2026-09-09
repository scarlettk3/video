### Copy-paste prompt

> I am attaching:
>
> 1. An IEEE research paper titled **“AI-Enabled Intelligent Defense for Link Flooding Attacks in Software Defined Networks”** by Qiang He et al.
> 2. A LaTeX Beamer presentation template used by the Department of Electronics and Communication Engineering, College of Engineering Trivandrum.
>
> I want you to create a **B.Tech project presentation** based on this research paper.
>
> **Very important distinction:**
>
> * Treat the IEEE paper only as the **BASE PAPER / reference paper**.
> * Treat our work as the **PROPOSED PROJECT**.
> * Do NOT present the complete implementation, numerical results, graphs, accuracy values, simulation results, or claims from the IEEE paper as results obtained by our project.
> * When information comes from the base paper, clearly identify it as **Base Paper / Reference Approach**.
> * When discussing our work, use wording such as **“Proposed System,” “Proposed Methodology,” “We propose to implement,” “Expected Outcome,” “Planned Implementation,”** etc.
> * Do not fabricate experimental results for our proposed project.
>
> ## Project topic
>
> Use a suitable project title based on:
>
> Evasion-Resilient Link Flooding Attack Detection in Software-Defined Networks Using Evolutionary Neural Architecture Search and GAN Augmentation
>
> or another concise academic title, while keeping the core topic unchanged.
>
> ## Base paper
>
> Study the attached IEEE paper thoroughly. The main ideas that should form the technical foundation of the project are:
>
> * Software Defined Networking (SDN)
> * Link Flooding Attack (LFA)
> * Limitations of conventional/statistical LFA detection
> * Fine-grained network monitoring
> * Network-flow and switch-status feature collection
> * In-band Network Telemetry (INT)
> * GAN-based attack/anomaly detection
> * Generator and discriminator operation
> * DDQN / Deep Reinforcement Learning
> * LFA mitigation through intelligent rerouting
> * Identification of suspicious attack-source IP addresses
> * Installation of SDN/OpenFlow rules for blocking malicious traffic
> * Restoration of normal routing after mitigation
>
> The proposed project should be a **practical academic prototype inspired by the base paper**, rather than a claim that we have recreated the entire research system.
>
> ## Mandatory presentation template
>
> **Use ONLY the following LaTeX Beamer presentation format and structure. Do not use a different visual template, theme, slide style, or organization.**
>
> Use:
>
> ```latex
> \documentclass{beamer}
> \mode<presentation>{
> \usetheme{Madrid}
> }
>
> \usepackage{graphicx}
> \usepackage{booktabs}
> \usepackage{textpos}
> ```
>
> Preserve the CET-style title slide format:
>
> ```latex
> \title[BTech Project]{\vspace{0.15cm}TITLE OF THE PROJECT}
>
> \author[Group 01]{ Project Group 01
> \newline \newline\scriptsize{
> Student 01 : TVE23EC00X
> \newline Student 02 : TVE23EC00X
> \newline Student 03 : TVE23EC00X
> \newline Student 04 : TVE23EC00X}
> \newline
> {\\\footnotesize{
> Under the Guidance of\\
> Prof(Dr).Name of Guide, Designation}}
> }
>
> \institute[CET]{
> \includegraphics[scale=0.25]{cet_emblem.PNG}\\
> \footnotesize{
> Dept. of Electronics and Communication Engineering\\
> College of Engineering, Trivandrum}
> }
>
> \scriptsize{\date{\today}}
> ```
>
> Keep placeholders for the student names, roll numbers, guide name and designation unless I provide them.
>
> ## Mandatory slide order
>
> Follow exactly this template structure:
>
> ```latex
> \input{slides/00_overview.tex}
> \input{slides/01_introduction}
> \input{slides/02_objectives}
> \input{slides/03_methodology}
> \input{slides/04_block_level_design}
> \input{slides/05_components_and_tools_used}
> \input{slides/06_implementation}
> \input{slides/07_final_Prototype_and_or_Results}
> \input{slides/08_workplan_and_task_allocation}
> \input{slides/09_conclusion}
> \input{slides/10_references}
> ```
>
> Therefore, organize the presentation under exactly these major sections:
>
> **1. Overview**
>
> Give a concise presentation roadmap containing:
>
> * Introduction
> * Objectives
> * Methodology
> * Block-Level Design
> * Components and Tools Used
> * Implementation
> * Final Prototype / Expected Results
> * Work Plan and Task Allocation
> * Conclusion
> * References
>
> **2. Introduction**
>
> Explain:
>
> * What SDN is
> * SDN control plane and data plane
> * Why centralized SDN control can be targeted by DDoS/LFA attacks
> * What a Link Flooding Attack is
> * Difference between conventional DDoS and LFA
> * Why LFA is difficult to detect because attack flows can resemble legitimate low-rate traffic
> * Need for intelligent detection and mitigation
>
> Include a clear **Problem Statement** slide.
>
> Include another slide titled **Base Paper** containing:
>
> * Paper title
> * Authors
> * Journal: IEEE Transactions on Computers
> * Year: 2026
> * DOI if appropriate
> * Core contribution of the paper
>
> Add a slide titled **Limitations / Research Gap Identified from Base Paper**, discussing issues relevant to a student implementation, such as:
>
> * computational complexity,
> * GAN/DDQN training requirements,
> * scalability,
> * real-time telemetry overhead,
> * complexity of reproducing a large-scale SDN testbed,
> * need for a simplified practical prototype.
>
> Do not criticize the paper inaccurately. Use limitations actually stated or reasonably arising from implementation complexity.
>
> **3. Objectives**
>
> Formulate our proposed-project objectives, for example:
>
> * Develop an SDN-based experimental environment for studying Link Flooding Attacks.
> * Monitor flow and link statistics from SDN switches.
> * Extract useful network features for attack detection.
> * Develop an AI/ML-based LFA detection module inspired by the GAN approach of the base paper.
> * Detect congested or targeted network links.
> * Develop an intelligent mitigation mechanism inspired by DDQN-based rerouting.
> * Identify suspicious traffic sources where practically feasible.
> * Install appropriate SDN/OpenFlow rules to reroute or block malicious traffic.
> * Evaluate the prototype using delay, throughput, packet-loss rate, detection accuracy, precision, recall and F1-score where applicable.
>
> Separate **Primary Objective** and **Specific Objectives** if useful.
>
> **4. Methodology**
>
> Clearly separate:
>
> **Base Paper Methodology**
>
> ```
> Network Monitoring
>       ↓
> INT-based Data Collection
>       ↓
> Feature Processing
>       ↓
> GAN / GLD Detection
>       ↓
> LFA Detected?
>       ↓
> Congested Link Identification
>       ↓
> DDQN-based Rerouting
>       ↓
> LFA Source Identification
>       ↓
> Flow Rule Installation / Blocking
> ```
>
> from:
>
> **Our Proposed Project Methodology**
>
> Create a realistic B.Tech implementation flow such as:
>
> ```
> SDN Test Network
>       ↓
> Traffic Generation
>       ↓
> Normal + LFA Traffic
>       ↓
> SDN Controller Monitoring
>       ↓
> Flow/Port Statistics Collection
>       ↓
> Data Preprocessing and Feature Extraction
>       ↓
> AI-Based LFA Detection
>       ↓
> Attack Decision
>       ↓
> Congested Link Identification
>       ↓
> Intelligent Rerouting / Mitigation
>       ↓
> Suspicious Source Blocking
>       ↓
> Network Performance Evaluation
> ```
>
> Explain the workflow in enough technical detail for a B.Tech project review.
>
> **5. Block-Level Design**
>
> Create a professional block diagram specifically for our **proposed system**, preferably containing:
>
> ```
> Traffic Generator / Hosts
>          |
>          v
> Mininet SDN Network
>          |
>          v
> OpenFlow Switches
>          |
>          v
> SDN Controller
>          |
>   +------+-------+
>   |              |
> Monitoring    Feature Extraction
>   |              |
>   +------v-------+
>          |
>    AI Detection Module
>          |
>     LFA Decision
>          |
>    Mitigation Module
>     /          \
> Rerouting    IP Blocking
>     \          /
>      SDN Flow Rules
>          |
> Performance Evaluation
> ```
>
> Improve this architecture if technically necessary.
>
> Include arrows and proper labels. The slide must be visually understandable rather than paragraph-heavy.
>
> Also include a **system flowchart** showing Normal Traffic versus Attack Traffic decisions.
>
> **6. Components and Tools Used**
>
> Use only tools that are realistic for the proposed implementation. Suitable candidates include:
>
> * Ubuntu/Linux
> * Python
> * Mininet
> * OpenFlow
> * Open vSwitch
> * SDN Controller such as Ryu or ONOS
> * Scapy / hping3 / iPerf for traffic generation where appropriate
> * Wireshark
> * NumPy / Pandas
> * Scikit-learn
> * TensorFlow or PyTorch
> * Matplotlib
>
> If full INT/P4 support is too complex for the initial B.Tech prototype, explicitly state whether it is:
>
> * implemented,
> * simplified,
> * emulated through controller statistics,
> * or reserved as future enhancement.
>
> Do not claim hardware components unless actually necessary.
>
> Include a table:
>
> | Component/Tool        | Purpose                                 |
> | --------------------- | --------------------------------------- |
> | Mininet               | SDN network emulation                   |
> | SDN Controller        | Central monitoring and control          |
> | Open vSwitch/OpenFlow | Packet forwarding and flow rules        |
> | Python                | Detection and mitigation implementation |
> | AI framework          | Model training/inference                |
> | iPerf/Scapy           | Traffic generation                      |
> | Wireshark             | Packet/network analysis                 |
>
> **7. Implementation**
>
> Since this is a **proposed project presentation**, distinguish between:
>
> * completed work,
> * currently planned work,
> * future implementation.
>
> Give a phased implementation:
>
> **Phase 1 – SDN Environment**
>
> * Construct Mininet topology
> * Configure switches and controller
> * Verify normal communication
>
> **Phase 2 – LFA Traffic Generation**
>
> * Generate legitimate background traffic
> * Generate distributed traffic designed to congest selected links
>
> **Phase 3 – Data Collection**
>
> * Collect flow statistics
> * Packet counts
> * Byte counts
> * Link utilization
> * Port statistics
> * Delay/latency if available
> * Queue/link information where feasible
>
> **Phase 4 – Data Processing**
>
> * Feature extraction
> * Cleaning
> * Normalization
> * Dataset creation
>
> **Phase 5 – LFA Detection**
>
> * Train/evaluate the selected AI model
> * Explain how the proposed approach is inspired by the GAN-based GLD mechanism
>
> **Phase 6 – Mitigation**
>
> * Find affected/congested link
> * Select alternate route
> * Install flow rules
> * Monitor suspicious sources
> * Block repeatedly identified malicious sources
>
> **Phase 7 – Evaluation**
>
> * Accuracy
> * Precision
> * Recall
> * F1-score
> * Packet loss
> * End-to-end delay
> * Throughput
> * Link utilization
> * Mitigation/recovery time
>
> Include pseudocode or compact algorithms only where they improve the presentation.
>
>
> **9. Work Plan and Task Allocation**
>
> Assume a team of four students.
>
> Provide a realistic work plan covering:
>
> * Literature survey
> * SDN/Mininet setup
> * Attack generation
> * Data collection
> * Detection-model development
> * Mitigation/rerouting
> * Integration
> * Testing
> * Result analysis
> * Documentation
> * Final presentation
>
> Include a clean work-plan/Gantt-style table.
>
> Suggest a balanced task allocation:
>
> * Student 1 – SDN topology and controller
> * Student 2 – attack generation and dataset/data collection
> * Student 3 – AI detection module
> * Student 4 – mitigation, integration and performance evaluation
>
> Mention that integration, testing, documentation and presentation are shared responsibilities.
>
> **10. Conclusion**
>
> The conclusion must describe the **proposed project**, not claim completed results.
>
> Explain that the project intends to provide an intelligent SDN defense architecture capable of:
>
> * monitoring,
> * LFA detection,
> * congestion identification,
> * intelligent mitigation,
> * malicious-source blocking,
> * network recovery.
>
> Include **Future Scope**, such as:
>
> * deployment on larger topologies,
> * P4/INT telemetry,
> * real-time online learning,
> * improved GAN architectures,
> * advanced DRL/DDQN routing,
> * distributed SDN controllers,
> * deployment on physical SDN hardware.
>
> **11. References**
>
> Put the IEEE base paper as the primary reference.
>
> Include only relevant references from the attached paper and other credible sources where required.
>
> Use IEEE reference format.
>
> ## Presentation quality requirements
>
> * Target approximately **18–25 slides**, unless additional slides are necessary.
> * Keep each slide concise.
> * Avoid long paragraphs.
> * Prefer 4–6 meaningful points per slide.
> * Use proper technical terminology.
> * Use diagrams, flowcharts, architecture figures and tables where useful.
> * Avoid decorative or irrelevant images.
> * Maintain an academic engineering-project-review style.
> * Make the slides understandable to ECE faculty members who may not specialize in AI or SDN.
> * Expand abbreviations the first time they appear.
> * Maintain consistent terminology throughout.
>
> ## Most important rule
>
> The **IEEE paper is the BASE PAPER**.
>
> The **B.Tech implementation is the PROPOSED PROJECT**.
>
> Never mix the two.
>
> Whenever necessary, explicitly use labels:
>
> **BASE PAPER**
>
> versus
>
> **PROPOSED SYSTEM**
>
> so the review panel can immediately understand the distinction.
>
> ## Output requirement
>
> Create the **complete presentation**, not just an outline.
>
> Use the supplied **Madrid Beamer/CET template only**.
>
> Provide:
>
> 1. Complete content for every slide.
> 2. The complete `.tex` structure following the supplied template.
> 3. Separate slide files:
>
>    * `00_overview.tex`
>    * `01_introduction.tex`
>    * `02_objectives.tex`
>    * `03_methodology.tex`
>    * `04_block_level_design.tex`
>    * `05_components_and_tools_used.tex`
>    * `06_implementation.tex`
>    * `07_final_Prototype_and_or_Results.tex`
>    * `08_workplan_and_task_allocation.tex`
>    * `09_conclusion.tex`
>    * `10_references.tex`
> 4. Suitable diagrams/block diagrams created for the presentation where necessary.
> 5. A final presentation that compiles correctly without overflowing text.
> 6. Keep the final slide:
>
> ```latex
> \begin{frame}
> \Huge{\centerline{The End}}
> \end{frame}
> ```
>
> **Do not change the template to another Beamer theme. Do not redesign it into a modern corporate presentation. Use the given CET Madrid Beamer template only.**
>
> If producing an editable PowerPoint `.pptx` instead of LaTeX, reproduce the visual appearance, section order, title-page structure, CET identity and Madrid-theme styling of the supplied template as closely as possible, and still provide the complete editable `.pptx`.
