(function(){

        window.MathJax = {
            loader: {load: ['[tex]/mhchem']}, // Loads the chemistry extension
            tex: { 
                packages: {'[+]': ['mhchem']}, // Activates the extension
                inlineMath: [['$', '$'], ['\\(', '\\)']], 
                displayMath: [['$$', '$$'], ['\\[', '\\]']] 
            },
            startup: { typeset: false } // We will trigger manually after DOM updates
        };
    
// =================

    const BACKEND_URL = "https://jee-mock-portal.onrender.com"; 
    
    // 1. Ultra-Forgiving Authenticate Guard
        // Looks for ANY saved token from login.html
        const token = localStorage.getItem("adminToken") || localStorage.getItem("token") || localStorage.getItem("studentToken"); 
        
        // Grabs name, but defaults to "Student" if your login.html saved it weirdly
        let studentName = localStorage.getItem("userName");
        if (!studentName || studentName === "undefined") {
            studentName = "Student"; 
        }

        // If there is absolutely no token, send them to login
        if (!token) {
            console.error("⛔ No login token found.");
            alert("You are not logged in! Redirecting to the Login page...");
            window.location.href = "login.html";
        }

        // Set Welcome Name globally
        document.getElementById("welcomeText").innerText = `👨‍🎓 ${studentName}`;

    // Global variable to store fetched past results data
    let myResultsData = [];


    // --- TAB SWITCHER LOGIC ---
    function switchTab(tabId, btnElement) {
        // 1. Hide all views
        document.querySelectorAll('.view-section').forEach(sec => {
            sec.classList.remove('active');
        });
        
        // 2. Remove active state from all buttons
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.remove('active');
        });

        // 3. Show target view and activate button
        document.getElementById(tabId).classList.add('active');
        btnElement.classList.add('active');

        // 4. Update the Page Title text dynamically
        const titleText = btnElement.innerText.replace(/[^\w\s]/gi, '').trim(); // Strips emojis
        document.getElementById('pageTitle').innerText = titleText;
        
        // Trigger tab-specific logic
        if (tabId === 'view-exams') {
            loadAvailableExams();
        } else if (tabId === 'view-past-results') {
            loadPastResults();
        }
    }


    // ============================================
    // TAB 1: MY AVAILABLE EXAMS LOGIC
    // ============================================
    async function loadAvailableExams() {
        const grid = document.getElementById("examGrid");
        grid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: #7f8c8d; font-style: italic;">Fetching available exams...</div>';
        
        try {
            const res = await fetch(`${BACKEND_URL}/api/public/exams`);
            if (!res.ok) throw new Error("Failed to fetch");
            
            const exams = await res.json();
            grid.innerHTML = ""; 

            if (exams.length === 0) {
                grid.innerHTML = `<div style="grid-column: 1/-1; background: white; padding: 40px; border-radius: 8px; text-align: center; color: #7f8c8d; font-style: italic;">No exams are currently active. Please check back later!</div>`;
                return;
            }

            let hasAvailableExams = false;

            // Fetch this student's PAST attempts to filter them out
            const pastResultsRes = await fetch(`${BACKEND_URL}/api/public/results/my-results`, { 
                headers: { "Authorization": `Bearer ${token}` } 
            });
            const attemptedExamsList = await pastResultsRes.json();
            const attemptedCountMap = {}; 

            attemptedExamsList.forEach(result => {
                const examId = result.examId;
                attemptedCountMap[examId] = (attemptedCountMap[examId] || 0) + 1;
            });

            // Check for saved exam progress (for admin-resumed exams and interrupted exams)
            const progressMap = {};  // examId -> { hasProgress, requiresAdminResume, adminApproved }
            for (const exam of exams) {
                try {
                    const progRes = await fetch(`${BACKEND_URL}/api/public/exams/${exam.id}/progress`, { 
                        headers: { "Authorization": `Bearer ${token}` } 
                    });
                    if (progRes.ok) {
                        const progData = await progRes.json();
                        if (progData.hasProgress) {
                            progressMap[exam.id] = {
                                requiresAdminResume: progData.requiresAdminResume || false,
                                adminApproved: progData.adminApproved || false
                            };
                        }
                    }
                } catch (e) {
                    // Silently ignore progress check failures
                }
            }

            exams.forEach(exam => {
                const qCount = exam.questionCount || 0;
                const isReady = qCount > 0;
                
                const attemptsOnThis = attemptedCountMap[exam.id] || 0;
                const isAttempted = attemptsOnThis > 0;

                // Check if any of the attempts was auto-submitted (for resume feature)
                let hasAutoSubmittedResult = false;
                if (attemptsOnThis > 0) {
                    const examResults = attemptedExamsList.filter(r => r.examId === exam.id);
                    hasAutoSubmittedResult = examResults.some(r => r.autoSubmitted === true);
                }

                // Check if there's saved progress and its status
                const progressInfo = progressMap[exam.id];
                const hasSavedProgress = !!progressInfo;
                const requiresAdminResume = progressInfo ? progressInfo.requiresAdminResume : false;
                const adminApproved = progressInfo ? progressInfo.adminApproved : false;

                // Skip rendering if already attempted and not auto-submitted and no saved progress
                if (isAttempted && !hasAutoSubmittedResult && !hasSavedProgress) {
                    return; 
                }

                // Case 1: Auto-submitted due to integrity violations, admin has NOT approved yet
                // The exam is marked as completed only - student CANNOT resume
                if (hasAutoSubmittedResult && (!hasSavedProgress || (requiresAdminResume && !adminApproved))) {
                    grid.innerHTML += `
                        <div class="exam-card" style="border-top-color: var(--danger);">
                            <div class="exam-title">
                                ${exam.title}
                                <span style="background: var(--danger); color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; margin-left: 8px; font-weight: bold;">🚫 COMPLETED</span>
                            </div>
                            <div class="exam-meta">
                                <span><b>Questions:</b> ${qCount}</span>
                                <span><b>Total Marks:</b> ${exam.totalMarks != null ? exam.totalMarks : (qCount * 4)}</span>
                            </div>
                            <button class="btn start-btn" style="background: #bbb; cursor: not-allowed;" disabled>⏳ Pending Admin Review</button>
                            <p style="font-size: 11px; color: #888; margin-top: 8px; text-align: center;">This exam was auto-submitted due to integrity violations. An admin must approve the resume before you can continue.</p>
                        </div>
                    `;
                    hasAvailableExams = true;
                    return;
                }

                // Case 2: Admin has approved the resume - student can continue
                if (hasAutoSubmittedResult && adminApproved) {
                    grid.innerHTML += `
                        <div class="exam-card" style="border-top-color: var(--secondary);">
                            <div class="exam-title">
                                ${exam.title}
                                <span style="background: var(--secondary); color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; margin-left: 8px; font-weight: bold;">🔄 RESUMED</span>
                            </div>
                            <div class="exam-meta">
                                <span><b>Questions:</b> ${qCount}</span>
                                <span><b>Total Marks:</b> ${exam.totalMarks != null ? exam.totalMarks : (qCount * 4)}</span>
                            </div>
                            <button class="btn btn-success start-btn" onclick="resumeExam('${exam.id}')">🔄 Continue Exam</button>
                            <p style="font-size: 11px; color: #888; margin-top: 8px; text-align: center;">An admin has resumed your exam. Continue from where you left off.</p>
                        </div>
                    `;
                    hasAvailableExams = true;
                    return;
                }

                // Case 3: Saved progress from interruption (power cut / accidental close) - auto-resume without admin
                if (hasSavedProgress && !requiresAdminResume && !hasAutoSubmittedResult) {
                    grid.innerHTML += `
                        <div class="exam-card" style="border-top-color: #f39c12;">
                            <div class="exam-title">
                                ${exam.title}
                                <span style="background: #f39c12; color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; margin-left: 8px; font-weight: bold;">🔄 IN PROGRESS</span>
                            </div>
                            <div class="exam-meta">
                                <span><b>Questions:</b> ${qCount}</span>
                                <span><b>Total Marks:</b> ${exam.totalMarks != null ? exam.totalMarks : (qCount * 4)}</span>
                            </div>
                            <button class="btn btn-success start-btn" onclick="resumeExam('${exam.id}')">🔄 Resume Exam</button>
                            <p style="font-size: 11px; color: #888; margin-top: 8px; text-align: center;">Your previous session was interrupted. You can resume from where you left off.</p>
                        </div>
                    `;
                    hasAvailableExams = true;
                    return;
                }

                const btnClass = isReady ? "start-btn btn-success" : "start-btn disabled";
                const btnText = isReady ? "Start Mock Test ▶" : "Exam Not Ready";
                const btnAction = isReady ? `onclick="startExam('${exam.id}')"` : "disabled";

            grid.innerHTML += `
                <div class="exam-card">
                    <div class="exam-title">${exam.title}</div>
                    <div class="exam-meta">
                        <span><b>Questions:</b> ${qCount}</span>
                        <span><b>Total Marks:</b> ${exam.totalMarks != null ? exam.totalMarks : (qCount * 4)}</span>
                    </div>
                    <button class="btn ${btnClass}" ${btnAction}>${btnText}</button>
                </div>
            `;
            
            hasAvailableExams = true;
        });

        // Show message if all exams have been attempted
        if (!hasAvailableExams && grid.innerHTML === "") {
            grid.innerHTML = `<div style="grid-column: 1/-1; background: #fff3cd; color: #856404; padding: 30px; border-radius: 8px; text-align: center; border: 1px solid #ffeeba;">
                <h3 style="margin-bottom: 10px;">All Exams Completed!</h3>
                <p>You have already attempted all available exams. Check your past results for analysis.</p>
                <button class="btn btn-outline" style="margin-top: 15px;" onclick="switchTab('view-past-results', document.querySelector('.nav-btn:nth-child(2)'))">View Past Results</button>
            </div>`;
            return;
        }

        } catch (error) {
            console.error("Error:", error);
            grid.innerHTML = `<div style="grid-column: 1/-1; background: #fdedec; color: #c0392b; padding: 20px; border-radius: 8px; text-align: center;">Unable to connect to the exam server. Please ensure your internet is active.</div>`;
        }
    }

    function startExam(examId) {
        if(confirm("Are you sure you want to start this exam? The timer will begin immediately.")) {
            window.location.href = `take_exam.html?id=${examId}`;
        }
    }

    async function resumeExam(examId) {
        if(!confirm("You have saved progress for this exam.\n\nDo you want to continue from where you left off? Your previous answers and progress will be restored.")) {
            return;
        }
        
        window.location.href = `take_exam.html?id=${examId}&resume=true`;
    }

    // ============================================
    // TAB 2: MY PAST RESULTS LOGIC
    // ============================================
    async function loadPastResults() {
        const resultsList = document.getElementById("pastResultsList");
        const loader = document.getElementById("resultsLoader");
        
        resultsList.innerHTML = "";
        loader.style.display = "block";

        try {
            const res = await fetch(`${BACKEND_URL}/api/public/results/my-results`, { 
                headers: { "Authorization": `Bearer ${token}` } 
            });
            if (!res.ok) throw new Error("Failed to fetch past results");
            
            myResultsData = await res.json();
            const results = myResultsData;
            
            loader.style.display = "none";

            if (results.length === 0) {
                resultsList.innerHTML = "<div style='padding: 25px; text-align: center; color: #7f8c8d; font-style: italic; background: white; border-radius: 0 0 6px 6px; border: 1px solid #eee;'>You haven't attempted any mock exams yet. Start one from the available list!</div>";
                return;
            }

            results.forEach(result => {
                let dateDisplay = "Unknown Date";
                if(result.submittedAt) {
                    const date = new Date(result.submittedAt);
                    dateDisplay = date.toLocaleDateString() + " " + date.toLocaleTimeString().substring(0,5);
                }

                // Check if this was auto-submitted
                const isAutoSubmitted = result.autoSubmitted || false;
                const autoBadge = isAutoSubmitted ? `<span style="background: var(--danger); color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; margin-left: 5px; font-weight: bold;">🚫 AUTO</span>` : '';
                
                // All results show only analysis button - no resume option in student portal
                const actionButton = `<button class="btn btn-primary" onclick="viewResultAnalysis('${result.id}')">View Detailed Analysis 📊</button>`;

                resultsList.innerHTML += `
                    <div class="result-item">
                        <div style="flex: 4; font-weight: bold; color: var(--primary);">${result.examTitle}${autoBadge}</div>
                        <div style="flex: 3; text-align: center; color: #777;">${dateDisplay}</div>
                        <div style="flex: 1; text-align: right; font-weight: bold; font-size: 16px; color: ${result.totalScore >= 0 ? 'var(--success)' : 'var(--danger)'};">${result.totalScore}</div>
                        <div style="width: 150px; text-align: right;">
                             ${actionButton}
                        </div>
                    </div>
                `;
            });

        // Render any LaTeX in exam titles once the results list is populated
        reRenderMathJax();

        } catch (e) {
            console.error("Could not load past results:", e);
            loader.style.display = "none";
            resultsList.innerHTML = "<div style='padding: 20px; color: #c0392b; background: #fdedec; border-radius: 6px; text-align: center;'>Unable to connect to results server. Please check your internet connection.</div>";
        }
    }

    
   // ============================================
    // MODAL: RESULT ANALYSIS LOGIC
    // ============================================
    async function viewResultAnalysis(resultId) {
        const resultData = myResultsData.find(r => r.id === resultId);
        if(!resultData) return alert("Result data not found.");

        document.getElementById("modalResultTitle").innerText = `Analysis: ${resultData.examTitle}`;
        
        let dateDisplay = "Unknown Date";
        if(resultData.submittedAt) {
            const date = new Date(resultData.submittedAt);
            dateDisplay = date.toLocaleDateString() + " " + date.toLocaleTimeString().substring(0,5);
        }
        document.getElementById("modalResultDate").innerText = `Submitted: ${dateDisplay} | Total Questions: ${resultData.examQuestionsCount}`;

        const container = document.getElementById("analysisContainer");
        const loader = document.getElementById("analysisLoader");
        
        container.innerHTML = "";
        loader.style.display = "block";
        document.getElementById("resultAnalysisModal").style.display = "flex";

        try {
            const res = await fetch(`${BACKEND_URL}/api/public/results/${resultId}/analysis`, {
                headers: { "Authorization": `Bearer ${token}` } 
            });
            if (!res.ok) throw new Error("Failed to fetch live ranking data");
            const liveData = await res.json();

            loader.style.display = "none";

            let rankHtml = `
                <div style="background: #f4f6f9; border-radius: 10px; padding: 20px; margin-bottom: 25px; border: 1px solid #e1e8ed;">
                    <h3 style="text-align: center; color: var(--primary); margin-bottom: 15px; font-size: 16px;">
                        🏆 OVERALL RANK <span style="color: #777; font-size: 14px;">(${liveData.totalStudents} STUDENTS)</span>
                    </h3>
                    <div style="display: flex; justify-content: space-around; text-align: center;">
                        <div>
                            <div style="font-size: 12px; color: #7f8c8d; font-weight: bold; text-transform: uppercase;">Total Score</div>
                            <div style="font-size: 24px; font-weight: bold; color: var(--primary);">${liveData.overall.myScore}</div>
                        </div>
                        <div style="border-left: 2px solid #ddd; padding-left: 20px;">
                            <div style="font-size: 12px; color: #e67e22; font-weight: bold; text-transform: uppercase;">Your Rank</div>
                            <div style="font-size: 24px; font-weight: bold; color: #d35400;">#${liveData.overall.rank}</div>
                        </div>
                        <div style="border-left: 2px solid #ddd; padding-left: 20px;">
                            <div style="font-size: 12px; color: #27ae60; font-weight: bold; text-transform: uppercase;">Top Score</div>
                            <div style="font-size: 24px; font-weight: bold; color: #27ae60;">${liveData.overall.top}</div>
                        </div>
                    </div>
                </div>
            `;
            container.innerHTML += rankHtml;

            // Anti-Cheat Violation Summary
            // Use liveData from the analysis endpoint (has smart detection for auto-submitted)
            // Fall back to resultData for older results
            const totalViolations = liveData.totalViolations || resultData.totalViolations || resultData.violationCount || 0;
            const totalAwayTime = liveData.totalAwayTime || resultData.totalAwayTime || 0;
            const autoSubmitted = liveData.autoSubmitted || resultData.autoSubmitted || false;
            const autoSubmitReason = liveData.autoSubmitReason || resultData.autoSubmitReason || '';
            const violationCount = (liveData.cheatingViolations && liveData.cheatingViolations.length) 
                ? liveData.cheatingViolations.length 
                : (resultData.cheatingViolations ? resultData.cheatingViolations.length : totalViolations);

            if (totalViolations > 0 || totalAwayTime > 0) {
                const violationColor = totalViolations >= 3 ? 'var(--danger)' : (totalViolations > 0 ? '#e67e22' : 'var(--success)');
                container.innerHTML += `
                    <div style="background: white; border: 1px solid #eee; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid ${violationColor};">
                        <h3 style="color: var(--primary); margin-bottom: 15px; font-size: 16px;">🔒 Exam Integrity Report</h3>
                        <div style="display: flex; gap: 25px; flex-wrap: wrap; font-size: 14px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-size: 20px;">⚠️</span>
                                <div>
                                    <div style="font-weight: bold; color: ${violationColor};">${totalViolations} Violation${totalViolations !== 1 ? 's' : ''}</div>
                                    <div style="font-size: 12px; color: #888;">Out of 3 allowed</div>
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-size: 20px;">⏱️</span>
                                <div>
                                    <div style="font-weight: bold; color: #555;">${totalAwayTime}s away</div>
                                    <div style="font-size: 12px; color: #888;">Total time outside exam</div>
                                </div>
                            </div>
                            ${autoSubmitted ? `
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-size: 20px;">🚫</span>
                                <div>
                                    <div style="font-weight: bold; color: var(--danger);">Auto-Submitted</div>
                                    <div style="font-size: 12px; color: #888;">${autoSubmitReason}</div>
                                </div>
                            </div>` : ''}
                        </div>
                        ${violationCount > 0 ? `
                        <details style="margin-top: 12px;">
                            <summary style="font-size: 13px; color: #888; cursor: pointer;">View violation details (${violationCount})</summary>
                            <div style="margin-top: 8px; max-height: 150px; overflow-y: auto; background: #f9f9f9; border-radius: 6px; padding: 10px;">
                                ${(liveData.cheatingViolations || resultData.cheatingViolations || []).map(v => `
                                    <div style="padding: 4px 0; font-size: 12px; color: #555; border-bottom: 1px solid #eee;">
                                        <span style="font-weight: bold;">#${v.violationNumber}</span>
                                        <span style="color: #888;">${v.type}</span>
                                        <span style="color: #999; float: right;">${new Date(v.timestamp).toLocaleTimeString()}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </details>` : ''}
                    </div>
                `;
            }

            if (resultData.subjectWiseBreakdown) {
                for (const subject in resultData.subjectWiseBreakdown) {
                    const staticStats = resultData.subjectWiseBreakdown[subject];
                    const dynamicStats = liveData.subjects[subject] || { rank: "-", avg: 0, top: 0, myScore: staticStats.score };
                    
                    const totalMarks = staticStats.subjectTotalMarks || 1;
                    
                    const youWidth = Math.max(5, (dynamicStats.myScore / totalMarks) * 100);
                    const avgWidth = Math.max(5, (dynamicStats.avg / totalMarks) * 100);
                    const topWidth = Math.max(5, (dynamicStats.top / totalMarks) * 100);

                    let subColor = "var(--secondary)"; 
                    if(subject.toLowerCase().includes("chem")) subColor = "var(--success)"; 
                    if(subject.toLowerCase().includes("math")) subColor = "#8e44ad"; 

                    container.innerHTML += `
                        <div style="background: white; border: 1px solid #eee; border-radius: 8px; padding: 20px; margin-bottom: 15px; border-left: 5px solid ${subColor};">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                                <div style="font-weight: bold; color: ${subColor}; font-size: 18px;">${subject}</div>
                                <div style="font-size: 14px; font-weight: bold; background: #fdf2e9; color: #d35400; padding: 4px 10px; border-radius: 4px;">Subject Rank: #${dynamicStats.rank}</div>
                            </div>
                            
                            <div style="display: flex; align-items: center; gap: 30px; margin-bottom: 20px;">
                                <div style="width: 80px; height: 80px; border-radius: 50%; border: 6px solid ${subColor}; display: flex; flex-direction: column; justify-content: center; align-items: center;">
                                    <span style="font-size: 20px; font-weight: bold; color: ${subColor};">${dynamicStats.myScore}</span>
                                    <span style="font-size: 10px; color: #777;">out of ${totalMarks}</span>
                                </div>
                                
                                <div style="flex: 1; font-size: 13px;">
                                    <div style="margin-bottom: 8px;">
                                        <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                                            <span><b>You</b></span><span>${dynamicStats.myScore}</span>
                                        </div>
                                        <div style="background: #eee; height: 8px; border-radius: 4px; width: 100%;">
                                            <div style="background: ${subColor}; height: 8px; border-radius: 4px; width: ${youWidth}%;"></div>
                                        </div>
                                    </div>
                                    <div style="margin-bottom: 8px;">
                                        <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                                            <span style="color: #7f8c8d;">Average</span><span style="color: #7f8c8d;">${dynamicStats.avg}</span>
                                        </div>
                                        <div style="background: #eee; height: 6px; border-radius: 3px; width: 100%;">
                                            <div style="background: #bdc3c7; height: 6px; border-radius: 3px; width: ${avgWidth}%;"></div>
                                        </div>
                                    </div>
                                    <div>
                                        <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                                            <span style="color: #27ae60;">Top Score</span><span style="color: #27ae60;">${dynamicStats.top}</span>
                                        </div>
                                        <div style="background: #eee; height: 6px; border-radius: 3px; width: 100%;">
                                            <div style="background: #2ecc71; height: 6px; border-radius: 3px; width: ${topWidth}%;"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div style="display: flex; gap: 20px; font-size: 13px; background: #fdfdfd; padding: 10px; border-radius: 6px; border: 1px solid #f0f0f0;">
                                <div style="color: #555;"><b>✅ Correct:</b> ${staticStats.correct}</div>
                                <div style="color: var(--danger);"><b>❌ Incorrect:</b> ${staticStats.incorrect}</div>
                                <div style="color: #8e44ad;"><b>⚪ Skipped:</b> ${staticStats.notAttempted}</div>
                            </div>
                        </div>
                    `;
                }
            }

            // Subject Time Summary
            if (liveData.subjectTimes && Object.keys(liveData.subjectTimes).length > 0) {
                container.innerHTML += `
                    <h3 style="color: var(--primary); margin: 25px 0 15px 0; font-size: 16px;">
                        ⏱️ Time Spent Per Subject
                    </h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin-bottom: 20px;">
                `;
                const totalTime = Object.values(liveData.subjectTimes).reduce((a, b) => a + b, 0);
                let subColors = { "physics": "var(--secondary)", "chemistry": "var(--success)", "maths": "#8e44ad" };
                for (const subject in liveData.subjectTimes) {
                    const secs = liveData.subjectTimes[subject];
                    const mins = Math.floor(secs / 60);
                    const remainingSecs = secs % 60;
                    const pct = totalTime > 0 ? (secs / totalTime * 100) : 0;
                    let color = "var(--secondary)";
                    for (const key in subColors) {
                        if (subject.toLowerCase().includes(key)) color = subColors[key];
                    }
                    container.innerHTML += `
                        <div style="background: white; border: 1px solid #eee; border-radius: 8px; padding: 15px; border-left: 4px solid ${color};">
                            <div style="font-weight: bold; color: ${color}; margin-bottom: 8px;">${subject}</div>
                            <div style="font-size: 22px; font-weight: bold;">${mins}:${remainingSecs.toString().padStart(2, '0')}</div>
                            <div style="font-size: 12px; color: #777;">${pct.toFixed(0)}% of total time</div>
                            <div style="background: #eee; height: 6px; border-radius: 3px; margin-top: 8px;">
                                <div style="background: ${color}; height: 6px; border-radius: 3px; width: ${pct}%;"></div>
                            </div>
                        </div>
                    `;
                }
                container.innerHTML += `</div>`;
            }

            // Question-wise Analysis Section
            if (liveData.questionAnalysis && liveData.questionAnalysis.length > 0) {
                container.innerHTML += `
                    <div class="analysis-section-head">
                        <h3 style="color: var(--primary); margin: 0; font-size: 16px;">📝 Question-wise Detailed Analysis</h3>
                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                            <button type="button" style="cursor:pointer; background:#eef3fa; border:1px solid #cfd8e3; border-radius:5px; padding:6px 12px; font-size:12px; font-weight:600; color:#1e3d59;" onclick="toggleAllQuestionAnalysis(true)">⬇ Expand All</button>
                            <button type="button" style="cursor:pointer; background:#fff; border:1px solid #cfd8e3; border-radius:5px; padding:6px 12px; font-size:12px; font-weight:600; color:#1e3d59;" onclick="toggleAllQuestionAnalysis(false)">⬆ Collapse All</button>
                        </div>
                    </div>
                    <p style="color:#888; font-size:13px; margin: 0 0 12px 0;">Click any question card to see the question text, your answer and the full solution.</p>
                `;

                liveData.questionAnalysis.forEach((qa, index) => {
                    const isCBSE = String(liveData.examType || resultData.examType || '').toLowerCase().includes('cbse');
                    const isSkipped = !qa.isAttempted;
                    const isManualQ = qa.questionType === 'subjective' || qa.questionType === 'case-based' || (!isCBSE && qa.marks > 1);

                    let statusText, statusBadgeClass, statusClass;
                    if (qa.subQuestions && qa.subQuestions.length) {
                        statusText = qa.isAttempted ? (qa.isCorrect ? 'Correct' : 'Attempted') : 'Skipped';
                        statusBadgeClass = qa.isCorrect ? 'correct' : (isSkipped ? 'skipped' : 'incorrect');
                    } else if (isManualQ) {
                        statusText = qa.isAttempted ? (qa.awardedMarks !== null && qa.awardedMarks !== undefined ? 'Evaluated' : 'Pending Eval') : 'Skipped';
                        statusBadgeClass = qa.isAttempted ? (qa.awardedMarks !== null && qa.awardedMarks !== undefined ? 'evaluated' : 'pending') : 'skipped';
                    } else {
                        statusText = qa.isCorrect ? 'Correct' : (isSkipped ? 'Skipped' : 'Incorrect');
                        statusBadgeClass = qa.isCorrect ? 'correct' : (isSkipped ? 'skipped' : 'incorrect');
                    }
                    statusClass = statusBadgeClass;

                    let marks;
                    if (qa.subQuestions && qa.subQuestions.length) {
                        marks = `${qa.scoredMarks || 0}/${qa.marks}`;
                    } else if (isManualQ) {
                        marks = (qa.awardedMarks !== null && qa.awardedMarks !== undefined) ? `${qa.awardedMarks}` : (qa.isAttempted ? 'Pending' : '—');
                    } else {
                        marks = qa.isCorrect ? `+${qa.marks || 1}` : (isSkipped ? '0' : (isCBSE ? '0' : '-1'));
                    }
                    
                    // Format time spent on this question
                    let timeDisplay = '';
                    if (qa.timeSpent !== null && qa.timeSpent !== undefined) {
                        const mins = Math.floor(qa.timeSpent / 60);
                        const secs = qa.timeSpent % 60;
                        timeDisplay = `${mins}:${secs.toString().padStart(2, '0')}`;
                    }

                    let subColor = "var(--secondary)";
                    const qSubjectLower = String(qa.subject || '').toLowerCase();
                    if(qSubjectLower.includes("chem")) subColor = "var(--success)";
                    if(qSubjectLower.includes("math")) subColor = "#8e44ad";

                    // Build options display
                    let optionsDisplay = '';
                    if (qa.options && qa.options.length > 0) {
                        optionsDisplay = '<div style="margin: 10px 0;"><strong>Options:</strong></div>';
                        qa.options.forEach((opt, idx) => {
                            const letter = String.fromCharCode(65 + idx);
                            const isCorrectOpt = qa.correctAnswer === opt;
                            const isSelectedOpt = qa.studentAnswer === opt;
                            let bg = 'white';
                            let border = '1px solid #ddd';
                            if (isCorrectOpt && isSelectedOpt) { bg = '#e8f8e5'; border = '2px solid var(--success)'; }
                            else if (isCorrectOpt) { bg = '#e8f8e5'; border = '2px solid var(--success)'; }
                            else if (isSelectedOpt) { bg = '#ffebee'; border = '2px solid var(--danger)'; }
                            let optImgHtml = (qa.optionImages && qa.optionImages[idx]) ? `<img src="${qa.optionImages[idx]}" class="opt-img" style="max-width: 100px; max-height: 60px; display: block; margin-top: 5px; cursor: zoom-in;" onclick="openZoom(this.src)">` : '';
                            optionsDisplay += `<div style="padding: 8px; margin: 4px 0; border-radius: 4px; background: ${bg}; border: ${border}; font-size: 14px;">${letter}. ${opt} ${isCorrectOpt ? '✅' : ''} ${isSelectedOpt && !isCorrectOpt ? '❌' : ''}${optImgHtml}</div>`;
                        });
                    }

                    // Build solution image HTML with zoom
                    let solutionImgHtml = '';
                    if (qa.solutionImage) {
                        solutionImgHtml = `
                            <div class="solution-image-wrapper">
                                <img src="${qa.solutionImage}" onclick="openZoom(this.src)" alt="Solution Image">
                            </div>
                        `;
                    }

                    container.innerHTML += `
                        <div class="question-analysis-card">
                            <div class="question-analysis-header ${statusClass} qa-card-header" onclick="toggleQuestionAnalysis(this)" title="Click to expand question details & solution">
                                <div style="display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
                                    <span style="font-weight: bold; color: var(--primary);">Q${index + 1}</span>
                                    <span style="font-size: 13px; padding: 2px 8px; border-radius: 12px; background: ${subColor}; color: white;">${qa.subject || 'General'}</span>
                                    ${safeList(qa.topics).length ? `<span style="font-size: 12px; color: #f39c12;">🏷️ ${safeList(qa.topics).slice(0, 3).join(', ')}</span>` : ''}
                                    ${timeDisplay ? `<span style="font-size: 12px; color: #888;">⏱️ ${timeDisplay}</span>` : ''}
                                    ${qa.marks ? `<span style="font-size: 12px; padding: 2px 8px; border-radius: 12px; background: #9b59b6; color: white;">${qa.marks} marks</span>` : ''}
                                </div>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <span style="font-weight: bold; color: ${qa.isCorrect ? 'var(--success)' : (isManualQ ? '#e67e22' : 'var(--danger)')};">${marks}</span>
                                    <span class="status-badge ${statusBadgeClass}">${statusText}</span>
                                    <span class="qa-arrow" style="font-size: 18px; color: #999;">▼</span>
                                </div>
                            </div>
                            <div class="question-analysis-body">
                                <div class="question-text">
                                    <span style="color: #666; font-size: 13px;">${qa.subject || 'General'} | Topics: ${safeList(qa.topics).length ? safeList(qa.topics).join(', ') : 'N/A'}</span><br><br>
                                    ${qa.question}
                                    ${qa.questionImage ? `<br><img src="${qa.questionImage}" style="max-width: 100%; max-height: 200px; border-radius: 4px; margin-top: 10px; cursor: zoom-in;" onclick="openZoom(this.src)">` : ''}
                                </div>
                                ${optionsDisplay}
                                ${qa.subQuestions && qa.subQuestions.length ? `
                                <div style="margin-top:10px;">
                                    ${qa.casePassage ? `<div class="case-passage"><strong>📖 Passage:</strong><br>${qa.casePassage}</div>` : ''}
                                    <div style="margin:10px 0;font-weight:600;color:var(--primary);">Sub-Questions</div>
                                    ${qa.subQuestions.map((sq, si) => {
                                        let sOpts = '';
                                        (sq.options || []).forEach((opt, oi) => {
                                            const letter = String.fromCharCode(65 + oi);
                                            const isCorr = sq.correctAnswer === opt;
                                            const isSel = sq.studentAnswer === opt;
                                            let bg = '#f9f9f9', bd = '1px solid #ddd', mark = '';
                                            if (isCorr && isSel) { bg = '#e8f8e5'; bd = '2px solid var(--success)'; mark = '✅'; }
                                            else if (isCorr) { bg = '#e8f8e5'; bd = '2px solid var(--success)'; mark = '✓'; }
                                            else if (isSel) { bg = '#ffebee'; bd = '2px solid var(--danger)'; mark = '❌'; }
                                            sOpts += `<div style="padding:6px;border-radius:4px;background:${bg};border:${bd};font-size:13px;margin:4px 0;">${letter}. ${opt} <strong>${mark}</strong></div>`;
                                        });
                                        const sStatus = sq.isCorrect ? '✅ Correct' : (sq.isAttempted ? '❌ Incorrect' : '— Not Attempted');
                                        let sAns = '';
                                        if (sq.studentAnswer && sq.type === 'subjective') {
                                            const sText = typeof sq.studentAnswer === 'object' ? (sq.studentAnswer.text || '') : sq.studentAnswer;
                                            if (sText) sAns = `<div style="margin-top:6px;font-size:13px;"><strong>Your answer:</strong> ${sText}</div>`;
                                        }
                                        return `<div class="analysis-sub-block" style="padding:10px;border:1px solid #e0e0e0;border-radius:6px;margin:8px 0;background:#fafbfc;">
                                            <div style="font-weight:600;color:var(--primary);">(${String.fromCharCode(97 + si)}) ${sq.subQuestion} <span style="color:#8e44ad;font-size:12px;">[${sq.marks} mark${sq.marks > 1 ? 's' : ''}]</span> <span style="font-size:12px;color:#555;">${sStatus}${sq.scoredMarks !== undefined && sq.scoredMarks !== null ? ' — ' + sq.scoredMarks + '/' + sq.marks + ' marks' : ''}</span></div>
                                            ${sOpts}
                                            ${sAns}
                                        </div>`;
                                    }).join('')}
                                    ${qa.scoredMarks !== undefined && qa.scoredMarks !== null ? `<div style="font-size:13px;color:#555;margin-top:4px;">Total earned: <strong>${qa.scoredMarks} / ${qa.marks}</strong> marks</div>` : ''}
                                </div>` : ''}
                                ${(qa.hint || (Array.isArray(qa.hints) && qa.hints.length)) ? `<div class="hint-box">${qa.hint || qa.hints.join(' ')}</div>` : ''}
                                <div class="answer-comparison">
                                    <div class="answer-box your-answer">
                                        <div style="font-size: 12px; color: #666; margin-bottom: 5px; font-weight: bold;">Your Answer</div>
                                        <div style="font-size: 16px; font-weight: bold; color: ${qa.isCorrect ? 'var(--success)' : (isManualQ ? '#e67e22' : 'var(--danger)')};">
                                            ${qa.isAttempted ? (typeof qa.studentAnswer === 'object' && qa.studentAnswer ? (qa.studentAnswer.text || '') : qa.studentAnswer) : '<span style="color: #999;">Not Attempted</span>'}
                                        </div>
                                    </div>
                                    <div class="answer-box correct-answer">
                                        <div style="font-size: 12px; color: #666; margin-bottom: 5px; font-weight: bold;">Correct Answer</div>
                                        <div style="font-size: 16px; font-weight: bold; color: var(--success);">${qa.correctAnswer}</div>
                                    </div>
                                </div>
                                ${qa.solution || solutionImgHtml ? `
                                <div class="solution-container">
                                    <div class="solution-header">
                                        <div class="solution-icon">${qa.solution ? '💡' : '🖼'}</div>
                                        <div class="solution-title">${qa.solution ? 'Detailed Solution' : 'Solution Image'}</div>
                                    </div>
                                    <div class="solution-content">
                                        ${qa.solution ? enhanceSolutionText(qa.solution) : ''}
                                        ${solutionImgHtml}
                                    </div>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    `;
                });
            }

        } catch(e) {
            console.error(e);
            loader.style.display = "none";
            container.innerHTML = `<div style="padding: 20px; color: #c0392b; background: #fdedec; text-align: center; border-radius: 6px;">Failed to load live ranking data. Check your internet connection.</div>`;
        }
        
        // Render MathJax after content is loaded
        renderMathInElement(container);
        reRenderMathJax();
    }

    // Return a reliable list from topics/hints-like values (some CSV imports store a plain string)
    function safeList(value) {
        if (Array.isArray(value)) return value.filter(Boolean);
        if (typeof value === 'string' && value.trim()) {
            return value.split(/[,;\n]+/).map(s => s.trim()).filter(Boolean);
        }
        return [];
    }

    // Helper function to enhance solution text with step/formula formatting.
    // Produces BALANCED HTML and preserves the $...$ / $$...$$ delimiters so
    // MathJax renders the LaTeX cleanly instead of showing raw code.
    function enhanceSolutionText(solutionText) {
        if (!solutionText) return '';
        let text = String(solutionText).replace(/\r\n?/g, '\n');

        // 1) Protect math blocks so the step splitter below can never mangle them
        const mathStore = [];
        text = text.replace(/\$\$[\s\S]+?\$\$/g, (m) => {
            mathStore.push(m);
            return '\u0001M' + (mathStore.length - 1) + '\u0001';
        });
        text = text.replace(/\$(?!\d)[^$\n]+\$/g, (m) => {
            mathStore.push(m);
            return '\u0001M' + (mathStore.length - 1) + '\u0001';
        });

        // 2) Normalise paragraph / line boundaries
        text = text.replace(/<\/p>/gi, '</p>\n').replace(/<br\s*\/?>/gi, '\n');

        const lines = text.split('\n');
        const parts = [];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const trimmed = line.trim();
            if (!trimmed) { parts.push(''); continue; }

            // Detect step markers: "Step 1:", "1.", "2)" - either at the start of a
            // line or after a short prefix such as "Solution: <p>Step 1: ...".
            let stepMatch = trimmed.match(/Step\s+(\d+)\s*[:：.)]/i);
            if (!stepMatch) {
                stepMatch = trimmed.match(/^(?:<[^>]*>\s*)?(\d+)\s*[:：.)]\s+(?!\d)/);
            }

            if (stepMatch) {
                const markerStart = stepMatch.index;
                const num = stepMatch[1];
                const markerLen = stepMatch[0].length;

                // Any text before the marker stays in place (e.g. "Solution:")
                let prefix = trimmed.slice(0, markerStart).trim();
                if (/^<p\b/.test(prefix) && !/<\/p>\s*$/.test(prefix)) {
                    prefix = prefix.replace(/^<p[^>]*>/i, '').trim();
                }
                if (/[：:]$/.test(prefix)) prefix = prefix.slice(0, -1);
                if (prefix) parts.push(prefix);

                const rest = trimmed.slice(markerStart + markerLen).trim().replace(/<\/p>\s*$/i, '');
                const badge = '<span class="solution-step-label">Step ' + num + '</span>';
                const body = /^<p\b/i.test(rest)
                    ? '<p>' + rest.replace(/^<p[^>]*>/i, '') + '</p>'
                    : '<div class="solution-step-text">' + rest + '</div>';
                parts.push('<div class="solution-step">' + badge + body + '</div>');
            } else {
                parts.push(trimmed);
            }
        }
        let html = parts.join('\n');

        // 3) Restore the protected math
        html = html.replace(/\u0001M(\d+)\u0001/g, (_, i) => mathStore[+i]);

        // 4) Box display math ($$...$$ preserved so MathJax renders display mode)
        html = html.replace(/\$\$([\s\S]+?)\$\$/g, (_, inner) => '<div class="solution-formula">$$' + inner + '$$</div>');

        // 5) Neat paragraph styling
        html = html.replace(/<p>/gi, '<p class="solution-para">');

        return html;
    }

    function toggleQuestionAnalysis(headerElement) {
        const body = headerElement.nextElementSibling;
        if (!body) return;
        body.classList.toggle('show');
        const arrow = headerElement.querySelector('.qa-arrow');
        if (arrow) arrow.innerText = body.classList.contains('show') ? '▲' : '▼';
        if (body.classList.contains('show')) renderMathInElement(body);
    }

    function toggleAllQuestionAnalysis(expand) {
        document.querySelectorAll('#resultAnalysisModal .question-analysis-body').forEach(b => b.classList.toggle('show', !!expand));
        document.querySelectorAll('#resultAnalysisModal .qa-arrow').forEach(a => a.innerText = expand ? '▲' : '▼');
        reRenderMathJax();
    }

    function closeResultAnalysis() { 
        document.getElementById("resultAnalysisModal").style.display = "none"; 
    }

    function reRenderMathJax() {
        if (window.MathJax && window.MathJax.typesetPromise) {
            // Clear and typeset all main content areas (MathJax v3 needs a real array, not a NodeList)
            const selector = '.question-text, .options-list, .hint-display, .hint-box, .case-passage, .modal-body, .result-content, .answer-box, .solution-content, .question-analysis-body, .analysis-option-row, .analysis-sub-block, #qText, #optionsList, #hintContainer, #analysisContainer, #adminAnalysisModal, #resultAnalysisModal, #pastResultsList';
            const mainAreas = Array.from(document.querySelectorAll(selector));
            mainAreas.forEach(el => MathJax.typesetClear([el]));
            MathJax.typesetPromise(mainAreas).catch((err) => console.log('MathJax error:', err));
        }
    }

    function renderMathInElement(container) {
        if (!container) return;
        if (window.MathJax && window.MathJax.typesetPromise) {
            MathJax.typesetClear([container]);
            MathJax.typesetPromise([container]).catch((err) => console.log('MathJax error:', err));
        }
    }
    
    // Enhanced MathJax configuration for better LaTeX support
    function initMathJax() {
        if (window.MathJax) {
            window.MathJax.startup.promise.then(() => {
                console.log('MathJax initialized successfully');
                reRenderMathJax();
            }).catch((err) => console.log('MathJax initialization error:', err));
        }
    }
    
    // Initialize MathJax on page load
    window.addEventListener('load', initMathJax);

    // ================= ZOOM FUNCTIONS FOR STUDENT PORTAL =================
    let studentZoomLevel = 100;

    function openZoom(src) {
        const img = document.getElementById("studentZoomImg");
        img.src = src;
        studentResetZoom();
        document.getElementById("studentZoomModal").style.display = "flex";
    }

    function studentCloseZoom() {
        document.getElementById("studentZoomModal").style.display = "none";
    }

    function studentChangeZoom(amount) {
        studentZoomLevel += amount;
        if (studentZoomLevel < 50) studentZoomLevel = 50;
        if (studentZoomLevel > 500) studentZoomLevel = 500;
        const img = document.getElementById("studentZoomImg");
        if (studentZoomLevel === 100) {
            img.style.maxWidth = "90%";
            img.style.maxHeight = "85vh";
            img.style.width = "auto";
        } else {
            img.style.maxWidth = "none";
            img.style.maxHeight = "none";
            img.style.width = studentZoomLevel + "%";
        }
    }

    function studentResetZoom() {
        studentZoomLevel = 100;
        const img = document.getElementById("studentZoomImg");
        img.style.maxWidth = "90%";
        img.style.maxHeight = "85vh";
        img.style.width = "auto";
    }

    function logout() {
        localStorage.clear();
        window.location.href = "login.html";
    }

    // 🔥 FIX: Check `token` here at the bottom to load the exams properly on start
    if (token) {
        loadAvailableExams();
    }

})();
