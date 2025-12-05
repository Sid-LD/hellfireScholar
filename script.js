// Application State
let appState = {
  currentUser: null,
  authMode: "login",
  activeTab: "dashboard",

  // Predefined subjects
  subjects: [
    "MICROPROCESSORS AND ITS APPLICATIONS",
    "ELECTROMAGNETIC THEORY",
    "SIGNALS AND SYSTEMS",
    "SOLID STATE DEVICES AND CIRCUITS",
  ],

  // Data stores
  notes: [],
  assignments: [],

  // Attendance data per subject
  attendance: {
    "MICROPROCESSORS AND ITS APPLICATIONS": {
      attended: 0,
      total: 0,
      required: 75,
    },
    "ELECTROMAGNETIC THEORY": { attended: 0, total: 0, required: 75 },
    "SIGNALS AND SYSTEMS": { attended: 0, total: 0, required: 75 },
    "SOLID STATE DEVICES AND CIRCUITS": { attended: 0, total: 0, required: 75 },
  },

  // Syllabus data per subject
  syllabus: {
    "MICROPROCESSORS AND ITS APPLICATIONS": {
      topics: [
        "ARCHITECTURE OF A 16-BIT MICROPROCESSOR",
        "CPU MODULE",
        "INTERRUPT HANDLING",
        "INTERFACING EXTERNAL DEVICES",
        "INTRODUCTION TO PENTIUM",
      ],
      completed: [],
    },
    "ELECTROMAGNETIC THEORY": {
      topics: [
        "CO-ORDINATE SYSTEM",
        "TIME VARYING ELECTROMAGNETIC FIELDS",
        "LINE WAVE PROPAGATION",
        "TRANSMISSION LINES",
        "WAVEGUIDES",
        "COMPUTATIONAL ELECTROMAGNETICS",
      ],
      completed: [],
    },
    "SIGNALS AND SYSTEMS": {
      topics: [
        "SIGNALS AND THEIR REPRESENTATION",
        "LINEAR TIME-INVARIANT (LTI) SYSTEMS",
        "FOURIER SERIES REPRESENTATION",
        "FOURIER TRANSFORMS",
        "LAPLACE TRANSFORMS",
        "Z-TRANSFORMS",
        "SAMPLING",
      ],
      completed: [],
    },
    "SOLID STATE DEVICES AND CIRCUITS": {
      topics: [
        "BIPOLAR JUNCTION TRANSISTOR",
        "MOSFET",
        "FEEDBACK AMPLIFIERS",
        "OSCILLATORS",
        "POWER AMPLIFIERS",
      ],
      completed: [],
    },
  },
};

// API Configuration
const API_URL = "http://localhost:3000/api";

// AUTHENTICATION FUNCTIONS
function switchAuthMode(mode) {
  appState.authMode = mode;

  const tabs = document.querySelectorAll(".auth-tab");
  tabs.forEach((tab) => tab.classList.remove("active"));
  event.target.classList.add("active");

  const registerFields = document.getElementById("registerFields");
  const buttonText = document.getElementById("authButtonText");

  if (mode === "register") {
    registerFields.style.display = "block";
    buttonText.textContent = "Create Account";
  } else {
    registerFields.style.display = "none";
    buttonText.textContent = "Login";
  }
}

async function handleAuth() {
  const email = document.getElementById("authEmail").value;
  const password = document.getElementById("authPassword").value;
  const authBtn = document.querySelector(".btn-primary");
  const originalBtnText = document.getElementById("authButtonText").innerText;

  if (!email || !password) {
    alert("Please fill in all fields");
    return;
  }

  // Prepare Request Data
  let endpoint = "/login";
  let bodyData = { email, password };

  if (appState.authMode === "register") {
    const name = document.getElementById("registerName").value;
    const course = document.getElementById("registerCourse").value;

    if (!name || !course) {
      alert("Please fill in name and course");
      return;
    }

    endpoint = "/register";
    bodyData = { ...bodyData, name, course };
  }

  try {
    // UI Feedback
    authBtn.disabled = true;
    document.getElementById("authButtonText").innerText = "Processing...";

    const response = await fetch(`${API_URL}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyData),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Authentication failed");
    }

    // Success: Store Token and User Data
    localStorage.setItem("authToken", data.token);
    localStorage.setItem("userData", JSON.stringify(data.user));

    // Update App State
    appState.currentUser = data.user;

    // UI Updates
    initializeAuthenticatedSession();
  } catch (error) {
    alert(error.message);
  } finally {
    authBtn.disabled = false;
    document.getElementById("authButtonText").innerText = originalBtnText;
  }
}

function initializeAuthenticatedSession() {
  const authScreen = document.getElementById("authScreen");
  const appScreen = document.getElementById("appScreen");

  // Update Name Display
  if (appState.currentUser) {
    document.getElementById("userName").textContent = appState.currentUser.name;
  }

  // Switch Screens
  authScreen.style.display = "none";
  appScreen.style.display = "block";

  // Load Data
  updateDashboard();
  renderNotes();
  renderSyllabus();
  renderAssignments();
  renderAttendance();
}

function logout() {
  // Clear State
  appState.currentUser = null;

  // Clear Storage
  localStorage.removeItem("authToken");
  localStorage.removeItem("userData");

  // Reset UI
  const authScreen = document.getElementById("authScreen");
  const appScreen = document.getElementById("appScreen");

  appScreen.style.display = "none";
  authScreen.style.display = "flex";

  // Clear Inputs
  document.getElementById("authEmail").value = "";
  document.getElementById("authPassword").value = "";
  document.getElementById("registerName").value = "";
  if (document.getElementById("registerCourse")) {
    document.getElementById("registerCourse").value = "";
  }
}

// NAVIGATION
function switchTab(tabName) {
  appState.activeTab = tabName;

  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach((item) => item.classList.remove("active"));
  event.target.closest(".nav-item").classList.add("active");

  const sections = document.querySelectorAll(".content-section");
  sections.forEach((section) => section.classList.remove("active"));
  document.getElementById(tabName).classList.add("active");
}

// ============================================
// MODAL FUNCTIONS
// ============================================

function openModal(modalType) {
  const modalId = modalType + "Modal";
  document.getElementById(modalId).classList.add("active");

  if (modalType === "addAssignment") {
    const today = new Date().toISOString().split("T")[0];
    document.getElementById("assignmentDeadline").value = today;
  }
}

function closeModal(modalType) {
  const modalId = modalType + "Modal";
  document.getElementById(modalId).classList.remove("active");
}

// Show/hide marks field based on assignment status
document.addEventListener("DOMContentLoaded", () => {
  const statusSelect = document.getElementById("assignmentStatus");
  if (statusSelect) {
    statusSelect.addEventListener("change", function () {
      const marksField = document.getElementById("marksField");
      if (this.value === "graded") {
        marksField.style.display = "block";
      } else {
        marksField.style.display = "none";
      }
    });
  }
});

// ============================================
// DASHBOARD FUNCTIONS
// ============================================

function updateDashboard() {
  document.getElementById("totalNotes").textContent = appState.notes.length;
  document.getElementById("pendingTasks").textContent =
    appState.assignments.filter((a) => a.status === "pending").length;

  // Calculate average attendance across all subjects
  let totalAttendance = 0;
  let subjectsWithData = 0;

  appState.subjects.forEach((subject) => {
    const att = appState.attendance[subject];
    if (att.total > 0) {
      totalAttendance += (att.attended / att.total) * 100;
      subjectsWithData++;
    }
  });

  if (subjectsWithData > 0) {
    document.getElementById("avgAttendance").textContent =
      Math.round(totalAttendance / subjectsWithData) + "%";
  } else {
    document.getElementById("avgAttendance").textContent = "--";
  }

  renderAttendanceAlerts();
}

function renderAttendanceAlerts() {
  const alertsContainer = document.getElementById("attendanceAlerts");

  const shortAttendance = appState.subjects.filter((subject) => {
    const att = appState.attendance[subject];
    return att.total > 0 && (att.attended / att.total) * 100 < att.required;
  });

  if (shortAttendance.length === 0) {
    alertsContainer.innerHTML =
      '<p style="color: #10b981;">All subjects meeting attendance requirements! 🎉</p>';
    return;
  }

  alertsContainer.innerHTML = shortAttendance
    .map((subject) => {
      const att = appState.attendance[subject];
      const percentage = ((att.attended / att.total) * 100).toFixed(1);
      const needed = calculateClassesNeeded(
        att.attended,
        att.total,
        att.required
      );
      return `
            <div class="alert">
                <div class="alert-icon">⚠️</div>
                <div class="alert-content">
                    <div class="alert-title">${subject}</div>
                    <div class="alert-text">Current: ${percentage}% | Need ${needed} more classes</div>
                </div>
            </div>
        `;
    })
    .join("");
}

// ============================================
// NOTES FUNCTIONS
// ============================================

function uploadNote() {
  const title = document.getElementById("noteTitle").value;
  const subject = document.getElementById("noteSubject").value;
  const category = document.getElementById("noteCategory").value;
  const file = document.getElementById("noteFile").files[0];

  if (!title || !file) {
    alert("Please fill in all fields");
    return;
  }

  const newNote = {
    id: Date.now(),
    title: title,
    subject: subject,
    category: category,
    fileName: file.name,
    uploadDate: new Date().toLocaleDateString(),
  };

  appState.notes.push(newNote);

  document.getElementById("noteTitle").value = "";
  document.getElementById("noteFile").value = "";

  closeModal("uploadNote");
  renderNotes();
  updateDashboard();
}

function renderNotes() {
  const notesGrid = document.getElementById("notesGrid");
  const filterValue = document.getElementById("notesFilter").value;

  // Filter notes based on selected subject
  const filteredNotes =
    filterValue === "all"
      ? appState.notes
      : appState.notes.filter((note) => note.subject === filterValue);

  if (filteredNotes.length === 0) {
    notesGrid.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📄</div>
                <p style="font-size: 18px; color: #94a3b8; margin-bottom: 8px;">No notes found</p>
                <p style="color: #64748b; font-size: 14px;">Upload notes for ${
                  filterValue === "all" ? "any subject" : filterValue
                }</p>
            </div>
        `;
    return;
  }

  notesGrid.innerHTML = filteredNotes
    .map(
      (note) => `
        <div class="note-card">
            <div class="note-header">
                <div>
                    <div class="note-title">${note.title}</div>
                    <div class="note-subject">${note.subject}</div>
                </div>
                <span class="badge badge-orange">${note.category}</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; color: #94a3b8; font-size: 14px; margin-top: 12px;">
                <span>${note.uploadDate}</span>
                <button onclick="deleteNote(${note.id})" style="background: none; border: none; color: #ef4444; cursor: pointer; font-size: 18px;">🗑️</button>
            </div>
        </div>
    `
    )
    .join("");
}

function deleteNote(noteId) {
  if (confirm("Are you sure you want to delete this note?")) {
    appState.notes = appState.notes.filter((n) => n.id !== noteId);
    renderNotes();
    updateDashboard();
  }
}

// ============================================
// SYLLABUS FUNCTIONS
// ============================================

function renderSyllabus() {
  const syllabusContainer = document.getElementById("syllabusContainer");
  const selectedSubject = document.getElementById(
    "syllabusSubjectSelect"
  ).value;
  const subjectData = appState.syllabus[selectedSubject];

  syllabusContainer.innerHTML = `
        <div class="card">
            <h3 class="card-title">${selectedSubject} - Topics</h3>
            <div style="display: grid; gap: 12px;">
                ${subjectData.topics
                  .map((topic, index) => {
                    const isCompleted = subjectData.completed.includes(topic);
                    return `
                        <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: ${
                          isCompleted ? "rgba(16, 185, 129, 0.1)" : "#0f172a"
                        }; border-radius: 8px; border: 1px solid ${
                      isCompleted ? "#10b981" : "#334155"
                    };">
                            <input 
                                type="checkbox" 
                                id="topic-${index}" 
                                ${isCompleted ? "checked" : ""}
                                onchange="toggleTopic('${selectedSubject}', '${topic}')"
                                style="width: 20px; height: 20px; cursor: pointer;"
                            />
                            <label for="topic-${index}" style="flex: 1; cursor: pointer; color: ${
                      isCompleted ? "#34d399" : "#e2e8f0"
                    }; font-weight: ${isCompleted ? "600" : "400"};">
                                ${topic}
                            </label>
                        </div>
                    `;
                  })
                  .join("")}
            </div>
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #334155;">
                <div style="display: flex; justify-content: between; align-items: center;">
                    <span style="color: #94a3b8;">Progress:</span>
                    <span style="color: #f97316; font-weight: 700; font-size: 20px;">${
                      subjectData.completed.length
                    }/${subjectData.topics.length} Topics</span>
                </div>
                <div class="progress-bar" style="margin-top: 12px;">
                    <div class="progress-fill" style="width: ${
                      (subjectData.completed.length /
                        subjectData.topics.length) *
                      100
                    }%"></div>
                </div>
            </div>
        </div>
    `;
}

function toggleTopic(subject, topic) {
  const subjectData = appState.syllabus[subject];
  const index = subjectData.completed.indexOf(topic);

  if (index > -1) {
    subjectData.completed.splice(index, 1);
  } else {
    subjectData.completed.push(topic);
  }

  renderSyllabus();
}

// ============================================
// ASSIGNMENTS FUNCTIONS
// ============================================

function addAssignment() {
  const title = document.getElementById("assignmentTitle").value;
  const subject = document.getElementById("assignmentSubject").value;
  const deadline = document.getElementById("assignmentDeadline").value;
  const status = document.getElementById("assignmentStatus").value;
  const marks = document.getElementById("assignmentMarks").value;

  if (!title || !deadline) {
    alert("Please fill in all required fields");
    return;
  }

  const newAssignment = {
    id: Date.now(),
    title: title,
    subject: subject,
    deadline: deadline,
    status: status,
    marks: status === "graded" && marks ? parseInt(marks) : null,
  };

  appState.assignments.push(newAssignment);

  document.getElementById("assignmentTitle").value = "";
  document.getElementById("assignmentDeadline").value = "";
  document.getElementById("assignmentStatus").value = "pending";
  document.getElementById("assignmentMarks").value = "";
  document.getElementById("marksField").style.display = "none";

  closeModal("addAssignment");
  renderAssignments();
  updateDashboard();
}

function renderAssignments() {
  const assignmentsContainer = document.getElementById("assignmentsContainer");

  if (appState.assignments.length === 0) {
    assignmentsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <p style="font-size: 18px; color: #94a3b8; margin-bottom: 8px;">No assignments yet</p>
                <p style="color: #64748b; font-size: 14px;">Click "Add Assignment" to track your coursework</p>
            </div>
        `;
    return;
  }

  assignmentsContainer.innerHTML = appState.assignments
    .map((assignment) => {
      const statusClass =
        assignment.status === "pending"
          ? "badge-yellow"
          : assignment.status === "submitted"
          ? "badge-blue"
          : "badge-green";
      const statusText =
        assignment.status.charAt(0).toUpperCase() + assignment.status.slice(1);

      return `
            <div class="card">
                <div class="assignment-header">
                    <div class="assignment-info">
                        <div class="assignment-title">${assignment.title}</div>
                        <div style="color: #94a3b8; margin-bottom: 8px;">${
                          assignment.subject
                        }</div>
                        <div style="color: #64748b; font-size: 14px;">
                            Deadline: ${new Date(
                              assignment.deadline
                            ).toLocaleDateString()}
                        </div>
                    </div>
                    <div style="text-align: right; display: flex; flex-direction: column; align-items: flex-end; gap: 8px;">
                        <span class="badge ${statusClass}">${statusText}</span>
                        ${
                          assignment.marks !== null
                            ? `<div class="assignment-marks">${assignment.marks}/100</div>`
                            : ""
                        }
                        <button onclick="deleteAssignment(${
                          assignment.id
                        })" style="background: none; border: none; color: #ef4444; cursor: pointer; font-size: 18px;">🗑️</button>
                    </div>
                </div>
            </div>
        `;
    })
    .join("");
}

function deleteAssignment(assignmentId) {
  if (confirm("Are you sure you want to delete this assignment?")) {
    appState.assignments = appState.assignments.filter(
      (a) => a.id !== assignmentId
    );
    renderAssignments();
    updateDashboard();
  }
}

// ============================================
// ATTENDANCE FUNCTIONS
// ============================================

function markAttendance(subject, status) {
  const att = appState.attendance[subject];
  att.total++;
  if (status === "present") {
    att.attended++;
  }

  renderAttendance();
  updateDashboard();
}

function calculateClassesNeeded(attended, total, required) {
  const currentPercentage = (attended / total) * 100;
  if (currentPercentage >= required) return 0;
  return Math.ceil((required * total - 100 * attended) / (100 - required));
}

function renderAttendance() {
  const attendanceContainer = document.getElementById("attendanceContainer");

  attendanceContainer.innerHTML = appState.subjects
    .map((subject) => {
      const att = appState.attendance[subject];
      const percentage =
        att.total > 0 ? ((att.attended / att.total) * 100).toFixed(1) : "--";
      const isShort =
        att.total > 0 && (att.attended / att.total) * 100 < att.required;
      const needed =
        att.total > 0
          ? calculateClassesNeeded(att.attended, att.total, att.required)
          : 0;

      return `
            <div class="attendance-subject-card">
                <div class="attendance-header">
                    <h3 class="attendance-subject-title">${subject}</h3>
                    <div class="attendance-buttons">
                        <button class="btn-present" onclick="markAttendance('${subject}', 'present')">
                            ✓ Present
                        </button>
                        <button class="btn-absent" onclick="markAttendance('${subject}', 'absent')">
                            ✗ Absent
                        </button>
                    </div>
                </div>
                
                <div class="attendance-details">
                    <div class="attendance-left">
                        <p style="color: #94a3b8; margin-bottom: 8px;">
                            ${att.attended} / ${att.total} classes attended
                        </p>
                    </div>
                    <div class="attendance-right">
                        <div class="attendance-percentage ${
                          isShort ? "red" : att.total > 0 ? "green" : ""
                        }" style="color: ${att.total === 0 ? "#94a3b8" : ""};">
                            ${percentage}${att.total > 0 ? "%" : ""}
                        </div>
                        <p style="color: #94a3b8; font-size: 14px;">Required: ${
                          att.required
                        }%</p>
                    </div>
                </div>
                
                ${
                  att.total > 0
                    ? `
                    <div class="progress-bar">
                        <div class="progress-fill ${
                          isShort ? "red" : "green"
                        }" style="width: ${Math.min(percentage, 100)}%"></div>
                    </div>
                `
                    : ""
                }
                
                ${
                  isShort
                    ? `
                    <div class="alert" style="margin-top: 12px;">
                        <div class="alert-icon">⚠️</div>
                        <div class="alert-content">
                            <p class="alert-text">Attend ${needed} more ${
                        needed === 1 ? "class" : "classes"
                      } to meet minimum requirement</p>
                        </div>
                    </div>
                `
                    : ""
                }
            </div>
        `;
    })
    .join("");
}

// Session Initialization
window.addEventListener("DOMContentLoaded", () => {
  // Check for saved session
  const token = localStorage.getItem("authToken");
  const storedUser = localStorage.getItem("userData");

  if (token && storedUser) {
    // Restore session
    appState.currentUser = JSON.parse(storedUser);
    initializeAuthenticatedSession();
  } else {
    // Show login
    document.getElementById("authScreen").style.display = "flex";
    document.getElementById("appScreen").style.display = "none";
  }

  console.log("🔥 Hellfire Scholar - Subject-wise Edition initialized! 📚");
});
