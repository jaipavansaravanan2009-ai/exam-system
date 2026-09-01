async function viewAdminAnalysis(resultId) {
        try {
            const res = await fetch(`${BACKEND_URL}/api/public/results/${resultId}/analysis`, { 
                headers: { "Authorization": `Bearer ${token}` } 
            });
            
            if (!res.ok) {
                alert("Could not load analysis for this result.");
                return;
            }
            
            const analysisData = await res.json();
            
            const modal = document.createElement('div');
            modal.id = 'adminAnalysisModal';
            modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 3000; backdrop-filter: blur(4px);';

            // ===== OVERALL PERFORMANCE =====
            const overallHTML = `
                <div style="background: #f4f6f9; border-radius: 10px; padding: 20px; margin-bottom: 25px; border: 1px solid #e1e8ed;">
                    <h3 style="text-align: center; color: var(--primary); margin-bottom: 15px; font-size: 16px;">
                        🏆 OVERALL PERFORMANCE <span style="color: #777; font-size: 14px;">(${analysisData.totalStudents || 0} STUDENTS)</span>
                    </h3>
                    <div style="display: flex; justify-content: space-around; text-align: center;">
                        <div>
                            <div style="font-size: 12px; color: #7f8c8d; font-weight: bold; text-transform: uppercase;">Total Score</div>
                            <div style="font-size: 24px; font-weight: bold; color: var(--primary);">${analysisData.overall ? analysisData.overall.myScore : 'N/A'}</div>
                        </div>
                        <div style="border-left: 2px solid #ddd; padding-left: 20px;">
                            <div style="font-size: 12px; color: #e67e22; font-weight: bold; text-transform: uppercase;">Rank</div>
                            <div style="font-size: 24px; font-weight: bold; color: #d35400;">#${analysisData.overall ? analysisData.overall.rank : 'N/A'}</div>
                        </div>
                        <div style="border-left: 2px solid #ddd; padding-left: 20px;">
                            <div style="font-size: 12px; color: #27ae60; font-weight: bold; text-transform: uppercase;">Top Score</div>
                            <div style="font-size: 24px; font-weight: bold; color: #27ae60;">${analysisData.overall ? analysisData.overall.top : 'N/A'}</div>
                        </div>
                        <div style="border-left: 2px solid #ddd; padding-left: 20px;">
                            <div style="font-size: 12px; color: #7f8c8d; font-weight: bold; text-transform: uppercase;">Total Students</div>
                            <div style="font-size: 24px; font-weight: bold; color: #7f8c8d;">${analysisData.totalStudents || 'N/A'}</div>
                        </div>
                    </div>
                </div>
            `;

            // ===== SUBJECT-WISE BREAKDOWN (live rank/avg/top) =====
            let subjectBreakdownHTML = '';
            if (analysisData.subjectWiseBreakdown) {
                for (const subject in analysisData.subjectWiseBreakdown) {
                    const staticStats = analysisData.subjectWiseBreakdown[subject];
                    const dynamicStats = (analysisData.subjects && analysisData.subjects[subject]) || { rank: "-", avg: 0, top: 0, myScore: staticStats.score };

                    const totalMarks = staticStats.subjectTotalMarks || 1;

                    const youWidth = Math.max(5, (dynamicStats.myScore / totalMarks) * 100);
                    const avgWidth = Math.max(5, (dynamicStats.avg / totalMarks) * 100);
                    const topWidth = Math.max(5, (dynamicStats.top / totalMarks) * 100);

                    let subColor = "var(--secondary)"; 
                    if(subject.toLowerCase().includes("chem")) subColor = "var(--success)"; 
                    if(subject.toLowerCase().includes("math")) subColor = "#8e44ad"; 

                    subjectBreakdownHTML += `
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

            // ===== EXAM INTEGRITY REPORT =====
            const violationData = analysisData.cheatingViolations || [];
            const totalViolations = analysisData.totalViolations || 0;
            const awayTime = analysisData.totalAwayTime || 0;
            const autoSubmitted = analysisData.autoSubmitted || false;
            const autoSubmitReason = analysisData.autoSubmitReason || '';
            const violationCount = violationData.length || totalViolations;

            let violationHTML = '';
            if (totalViolations > 0 || awayTime > 0) {
                const violationColor = totalViolations >= 3 ? 'var(--danger)' : (totalViolations > 0 ? '#e67e22' : 'var(--success)');
                violationHTML = `
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
                                    <div style="font-weight: bold; color: #555;">${awayTime}s away</div>
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
                                ${violationData.map(v => `
                                    <div style="padding: 4px 0; font-size: 12px; color: #555; border-bottom: 1px solid #eee;">
                                        <span style="font-weight: bold;">#${v.violationNumber}</span>
                                        <span style="color: #888;">${v.type}</span>
                                        <span style="color: #999; float: right;">${new Date(v.timestamp).toLocaleTimeString()}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </details>` : ''}
                        ${autoSubmitted ? `
                        <div style="margin-top: 15px; padding-top: 15px; border-top: 2px solid #eee; display: flex; gap: 10px; flex-wrap: wrap;">
                            <button class="btn btn-success" onclick="resumeExamFromAnalysis('${resultId}')" style="font-size: 14px; padding: 10px 20px;">
                                🔄 Resume Exam for Candidate
                            </button>
                            <button class="btn btn-outline" onclick="finishExamFromAnalysis('${resultId}')" style="font-size: 14px; padding: 10px 20px; border-color: #e74c3c; color: #e74c3c;">
                                🏁 Finish Exam
                            </button>
                            <p style="font-size: 12px; color: #888; margin-top: 8px; width: 100%;">Resume lets the student continue where they left off. Finish finalizes the result and clears saved progress.</p>
                        </div>
                        ` : ''}
                    </div>
                `;
            }

// ===== SUBJECT TIME SUMMARY =====
            let subjectTimeHTML = '';
            if (analysisData.subjectTimes && Object.keys(analysisData.subjectTimes).length > 0) {
                const totalTime = Object.values(analysisData.subjectTimes).reduce((a, b) => a + b, 0);
                subjectTimeHTML = `
                    <h3 style="color: var(--primary); margin: 25px 0 15px 0; font-size: 16px;">⏱️ Time Spent Per Subject</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin-bottom: 20px;">
                `;
                let subColors = { "physics": "var(--secondary)", "chemistry": "var(--success)", "maths": "#8e44ad" };
                for (const subject in analysisData.subjectTimes) {
                    const secs = analysisData.subjectTimes[subject];
                    const mins = Math.floor(secs / 60);
                    const remainingSecs = secs % 60;
                    const pct = totalTime > 0 ? (secs / totalTime * 100) : 0;
                    let color = "var(--secondary)";
                    for (const key in subColors) {
                        if (subject.toLowerCase().includes(key)) color = subColors[key];
                    }
                    subjectTimeHTML += `
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
                subjectTimeHTML += '</div>';
            }
// ===== QUESTION-WISE DETAILED ANALYSIS =====
            let questionAnalysisHTML = '';
            if (analysisData.questionAnalysis && analysisData.questionAnalysis.length > 0) {
                questionAnalysisHTML = `
                    <div class="analysis-section-head">
                        <h3 style="color: var(--primary); margin: 0; font-size: 16px;">📝 Question-wise Detailed Analysis</h3>
                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                            <button type="button" style="cursor:pointer; background:#eef3fa; border:1px solid #cfd8e3; border-radius:5px; padding:6px 12px; font-size:12px; font-weight:600; color:#1e3d59;" onclick="toggleAllQuestionAnalysis(true)">⬇ Expand All</button>
                            <button type="button" style="cursor:pointer; background:#fff; border:1px solid #cfd8e3; border-radius:5px; padding:6px 12px; font-size:12px; font-weight:600; color:#1e3d59;" onclick="toggleAllQuestionAnalysis(false)">⬆ Collapse All</button>
                        </div>
                    </div>
                    <p style="color:#888; font-size:13px; margin: 0 0 12px 0;">Click any question card to see the question text, the candidate's answer and the full solution.</p>
                `;

                analysisData.questionAnalysis.forEach((qa, index) => {
                    const isCBSE = String(analysisData.examType || '').toLowerCase().includes('cbse');
                    const isSkipped = !qa.isAttempted;
                    const isManualQ = qa.questionType === 'subjective' || qa.questionType === 'case-based' || (!isCBSE && qa.marks > 1);

                    let statusText, statusBadgeClass;
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

                    let marks;
                    if (qa.subQuestions && qa.subQuestions.length) {
                        marks = `${qa.scoredMarks || 0}/${qa.marks}`;
                    } else if (isManualQ) {
                        marks = (qa.awardedMarks !== null && qa.awardedMarks !== undefined) ? `${qa.awardedMarks}` : (qa.isAttempted ? 'Pending' : '—');
                    } else {
                        marks = qa.isCorrect ? `+${qa.marks || 1}` : (isSkipped ? '0' : (isCBSE ? '0' : '-1'));
                    }

                    let timeDisplay = '';
                    if (qa.timeSpent !== null && qa.timeSpent !== undefined) {
                        const mins = Math.floor(qa.timeSpent / 60);
                        const secs = qa.timeSpent % 60;
                        timeDisplay = `⏱️ ${mins}:${secs.toString().padStart(2, '0')}`;
                    }

                    let subColor = "var(--secondary)";
                    const qSubjectLower = String(qa.subject || '').toLowerCase();
                    if(qSubjectLower.includes("chem")) subColor = "var(--success)";
                    if(qSubjectLower.includes("math")) subColor = "#8e44ad";

                    // Build options display with correct/incorrect highlighting
                    let optionsDisplay = '';
                    if (qa.options && qa.options.length > 0) {
                        qa.options.forEach((opt, idx) => {
                            const letter = String.fromCharCode(65 + idx);
                            const isCorrectOpt = qa.correctAnswer === opt;
                            const isSelectedOpt = qa.studentAnswer === opt;
                            let cls = 'neutral', indicator = '';
                            if (isCorrectOpt && isSelectedOpt) { cls = 'correct'; indicator = '✅'; }
                            else if (isCorrectOpt) { cls = 'correct'; indicator = '✓'; }
                            else if (isSelectedOpt) { cls = 'wrong'; indicator = '❌'; }
                            let optImg = (qa.optionImages && qa.optionImages[idx]) ? `<br><img src="${qa.optionImages[idx]}" style="max-width: 120px; max-height: 80px; margin-top: 5px; border-radius: 4px; cursor: zoom-in;" onclick="openZoom(this.src)" alt="Option ${idx + 1} Image">` : '';
                            optionsDisplay += `<div class="analysis-option-row ${cls}">${letter}. ${opt} <strong>${indicator}</strong>${optImg}</div>`;
                        });
                    }

                    // Solution image HTML
                    let solutionImgHtml = '';
                    if (qa.solutionImage) {
                        solutionImgHtml = `<div class="solution-image-wrapper"><img src="${qa.solutionImage}" onclick="openZoom(this.src)" alt="Solution Image"></div>`;
                    }

                    // Question image
                    let qImgHtml = '';
                    if (qa.questionImage) {
                        qImgHtml = `<br><img src="${qa.questionImage}" style="max-width: 100%; max-height: 200px; border-radius: 4px; margin-top: 8px; cursor: zoom-in;" onclick="openZoom(this.src)" alt="Question Image">`;
                    }
// Section D (case-based) sub-question analysis
                    let subQuestionsHtml = '';
                    if (qa.subQuestions && qa.subQuestions.length) {
                        let subBlocks = '';
                        qa.subQuestions.forEach((sq, si) => {
                            let subOpts = '';
                            (sq.options || []).forEach((opt, oi) => {
                                const letter = String.fromCharCode(65 + oi);
                                const isCorr = sq.correctAnswer === opt;
                                const isSel = sq.studentAnswer === opt;
                                let sbg = '#f9f9f9', sbd = '1px solid #ddd', sind = '';
                                if (isCorr && isSel) { sbg = '#e8f8e5'; sbd = '2px solid var(--success)'; sind = '✅'; }
                                else if (isCorr) { sbg = '#e8f8e5'; sbd = '2px solid var(--success)'; sind = '✓'; }
                                else if (isSel) { sbg = '#ffebee'; sbd = '2px solid var(--danger)'; sind = '❌'; }
                                subOpts += `<div style="padding:6px;border-radius:4px;background:${sbg};border:${sbd};font-size:13px;margin:4px 0;">${letter}. ${opt} <strong>${sind}</strong></div>`;
                            });
                            const sStatus = sq.isCorrect ? '✅ Correct' : (sq.isAttempted ? '❌ Incorrect' : '— Not Attempted');
                            subBlocks += `
                                <div class="analysis-sub-block">
                                    <div style="font-weight:600;color:var(--primary);">(${String.fromCharCode(97 + si)}) ${sq.subQuestion} <span style="color:#8e44ad;font-size:12px;">[${sq.marks} mark${sq.marks > 1 ? 's' : ''}]</span> <span style="font-size:12px;color:#555;">${sStatus} — ${sq.scoredMarks}/${sq.marks} marks</span></div>
                                    ${subOpts}
                                </div>`;
                        });
                        subQuestionsHtml = `
                            ${qa.casePassage ? `<div class="case-passage"><strong>📖 Passage:</strong><br>${qa.casePassage}</div>` : ''}
                            <div style="margin:10px 0;font-weight:600;color:var(--primary);">Sub-Questions (auto-graded):</div>
                            ${subBlocks}
                            <div style="font-size:13px;color:#555;margin-top:4px;">Total earned: <strong>${qa.scoredMarks || 0} / ${qa.marks}</strong> marks</div>`;
                    }

                    // Answer image (for subjective questions) — ADMIN ONLY
                    let answerImageHtml = '';
                    if (qa.answerImage) {
                        answerImageHtml = `
                            <div class="answer-image-box">
                                <div style="font-size: 12px; font-weight: bold; color: var(--secondary); margin-bottom: 8px;">📸 Student's Answer Image</div>
                                <img src="${qa.answerImage}" style="max-width: 100%; max-height: 300px; border-radius: 6px; cursor: zoom-in;" onclick="openZoom(this.src)">
                            </div>
                        `;
                    }

                    // Manual evaluation UI (for subjective questions) — ADMIN ONLY
                    let manualEvaluationHtml = '';
                    if (!qa.subQuestions && (qa.questionType === 'subjective' || qa.questionType === 'case-based' || qa.marks > 1)) {
                        const maxMarks = qa.marks || 5;
                        const awardedMarks = qa.awardedMarks !== undefined ? qa.awardedMarks : null;
                        manualEvaluationHtml = `
                            <div class="manual-eval-box">
                                <div style="font-size: 13px; font-weight: bold; color: #d35400; margin-bottom: 8px;">✏️ Manual Evaluation (Max: ${maxMarks} marks - decimals allowed e.g. 1.5)</div>
                                <div id="marks-display-${index}" style="display: ${awardedMarks !== null ? 'block' : 'none'}; font-size: 16px; font-weight: bold; color: var(--success);">
                                    ${awardedMarks !== null ? `${awardedMarks}/${maxMarks} marks` : ''}
                                </div>
                                <div id="marks-input-${index}" style="display: ${awardedMarks !== null ? 'none' : 'block'};">
                                    <input type="number" id="marks-q-${index}" data-max-marks="${maxMarks}" value="0" min="0" max="${maxMarks}" step="0.25" 
                                        style="padding: 8px; width: 100px; border: 2px solid #f39c12; border-radius: 4px; font-size: 14px; font-weight: bold;">
                                    <button class="btn btn-small" style="background: var(--success); color: white; margin-left: 8px;" 
                                        onclick="updateSubjectiveMarks('${resultId}', ${index})">Save Marks</button>
                                </div>
                            </div>
                        `;
                    }

                    // Hint box
                    const hintText = qa.hint || (Array.isArray(qa.hints) && qa.hints.length ? qa.hints.join(' ') : '');
                    const hintHtml = hintText ? `<div class="hint-box">${hintText}</div>` : '';
questionAnalysisHTML += `
                        <div class="question-analysis-card">
                            <div class="question-analysis-header ${statusBadgeClass} qa-card-header" onclick="toggleQuestionAnalysis(this)" title="Click to expand question details & solution">
                                <div style="display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
                                    <span style="font-weight: bold; color: var(--primary);">Q${index + 1}</span>
                                    <span style="font-size: 13px; padding: 2px 8px; border-radius: 12px; background: ${subColor}; color: white;">${qa.subject || 'General'}</span>
                                    ${safeList(qa.topics).length ? `<span style="font-size: 12px; color: #f39c12;">🏷️ ${safeList(qa.topics).slice(0, 3).join(', ')}</span>` : ''}
                                    ${timeDisplay ? `<span style="font-size: 12px; color: #888;">${timeDisplay}</span>` : ''}
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
                                    ${qImgHtml}
                                </div>
                                ${subQuestionsHtml}
                                ${optionsDisplay}
                                ${hintHtml}
                                ${answerImageHtml}
                                ${manualEvaluationHtml}
                                ${!qa.subQuestions ? `
                                <div class="answer-comparison">
                                    <div class="answer-box your-answer">
                                        <div style="font-size: 12px; color: #666; margin-bottom: 5px; font-weight: bold;">Student Answer</div>
                                        <div style="font-size: 16px; font-weight: bold; color: ${qa.isCorrect ? 'var(--success)' : (isManualQ ? '#e67e22' : 'var(--danger)')};">${qa.isAttempted ? (typeof qa.studentAnswer === 'object' && qa.studentAnswer ? (qa.studentAnswer.text || '') : qa.studentAnswer) : '<span style="color: #999;">Not Attempted</span>'}</div>
                                    </div>
                                    <div class="answer-box correct-answer">
                                        <div style="font-size: 12px; color: #666; margin-bottom: 5px; font-weight: bold;">Correct Answer</div>
                                        <div style="font-size: 16px; font-weight: bold; color: var(--success);">${qa.correctAnswer}</div>
                                    </div>
                                </div>` : ''}
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
modal.innerHTML = `
                <div style="background: white; padding: 30px; border-radius: 12px; width: 90%; max-width: 950px; max-height: 90vh; overflow-y: auto;">
                    <button class="btn" style="float:right; background:#333; color:white;" onclick="this.parentElement.parentElement.remove()">Close X</button>
                    <h2 style="color: var(--primary); margin-bottom: 5px;">📊 Result Analysis</h2>
                    <p style="color: #777; font-size: 14px; margin-bottom: 20px;">Candidate: ${analysisData.studentName || 'Student'}</p>
                    <hr style="margin: 20px 0;">
                    
                    ${overallHTML}
                    ${subjectBreakdownHTML}
                    ${violationHTML}
                    ${subjectTimeHTML}
                    ${questionAnalysisHTML}
                </div>
            `;
            
            document.body.appendChild(modal);
            
            // Admin-only actions inside the analysis modal
            window.resumeExamFromAnalysis = async function(resultId) {
                if (!confirm("Are you sure you want to resume this exam?\n\nThe student will be able to continue from where they left off. Their previous answers and progress will be restored.")) {
                    return;
                }
                try {
                    const res = await fetch(`${BACKEND_URL}/api/admin/results/${resultId}/resume`, {
                        method: "POST",
                        headers: { "Authorization": `Bearer ${token}` }
                    });
                    const data = await res.json();
                    if (res.ok) {
                        alert("✅ Exam resumed successfully!\n\nThe student can now continue the exam from where they left off.");
                        modal.remove();
                        loadResults();
                    } else {
                        alert("Failed to resume exam: " + (data.detail || "Unknown error"));
                    }
                } catch (e) {
                    console.error("Error resuming exam:", e);
                    alert("Error resuming exam. Please try again.");
                }
            };

            window.finishExamFromAnalysis = async function(resultId) {
                if (!confirm("Are you sure you want to finish this exam?\n\nThis will finalize the result and clear any saved progress. The student will NOT be able to resume this exam.")) {
                    return;
                }
                try {
                    const res = await fetch(`${BACKEND_URL}/api/admin/results/${resultId}/finish`, {
                        method: "POST",
                        headers: { "Authorization": `Bearer ${token}` }
                    });
                    const data = await res.json();
                    if (res.ok) {
                        alert("✅ Exam finalized successfully!\n\nThe result has been marked as completed and saved progress has been cleared.");
                        modal.remove();
                        loadResults();
                    } else {
                        alert("Failed to finish exam: " + (data.detail || "Unknown error"));
                    }
                } catch (e) {
                    console.error("Error finishing exam:", e);
                    alert("Error finishing exam. Please try again.");
                }
            };

            // Manual evaluation function for subjective questions
            window.updateSubjectiveMarks = async function(resultId, questionIndex) {
                const marksInput = document.getElementById(`marks-q-${questionIndex}`);
                const marks = parseFloat(marksInput.value);
                const maxMarks = parseFloat(marksInput.getAttribute('data-max-marks'));
                if (isNaN(marks) || marks < 0 || marks > maxMarks) {
                    alert(`Please enter valid marks (0-${maxMarks})`);
                    return;
                }
                try {
                    const res = await fetch(`${BACKEND_URL}/api/admin/results/${resultId}/update-marks`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${token}`
                        },
                        body: JSON.stringify({
                            subjectiveMarks: {
                                [questionIndex]: marks
                            }
                        })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        const marksDisplay = document.getElementById(`marks-display-${questionIndex}`);
                        marksDisplay.innerHTML = `<span style="color: var(--success); font-weight: bold;">${marks}/${maxMarks}</span>`;
                        marksInput.style.display = 'none';
                        marksDisplay.style.display = 'block';
                        alert("Marks updated successfully! ✅");
                    } else {
                        alert("Failed to update marks: " + (data.detail || "Unknown error"));
                    }
                } catch (e) {
                    console.error("Error updating marks:", e);
                    alert("Error updating marks. Please try again.");
                }
            };

            // Render MathJax on the modal content
            renderMathInElement(modal);
            reRenderMathJax();
            
        } catch(e) {
            console.error(e);
            alert("Error loading analysis: " + e.message);
        }
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
        document.querySelectorAll('#adminAnalysisModal .question-analysis-body').forEach(b => b.classList.toggle('show', !!expand));
        document.querySelectorAll('#adminAnalysisModal .qa-arrow').forEach(a => a.innerText = expand ? '▲' : '▼');
        reRenderMathJax();
    }
