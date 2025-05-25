// --- API Base URL ---
const API_BASE_URL = 'http://localhost:3000/api'; // Ensure this matches your backend port

// --- DOM Elements ---
const authSection = document.getElementById('auth-section');
const dashboardSection = document.getElementById('dashboard-section');
const authTitle = document.getElementById('auth-title');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const toggleAuthText = document.getElementById('toggle-auth-text');
const toggleAuthModeBtn = document.getElementById('toggle-auth-mode');
const authMessage = document.getElementById('auth-message');
const loadingSpinner = document.getElementById('loading-spinner');

const userInfoSpan = document.getElementById('user-info');
const logoutBtn = document.getElementById('logout-btn');

const applyLeaveForm = document.getElementById('apply-leave-form');
const leaveTypeInput = document.getElementById('leave-type');
const startDateInput = document.getElementById('start-date');
const endDateInput = document.getElementById('end-date');
const applyLeaveMessage = document.getElementById('apply-leave-message');

// New DOM elements for leave calculation and reason
const daysOfLeaveDisplay = document.getElementById('days-of-leave-display');
const calculatedDaysSpan = document.getElementById('calculated-days');
const reasonSelect = document.getElementById('reason-select'); // The new select dropdown
const reasonGroup = document.getElementById('reason-group');   // The div containing the textarea
const reasonInput = document.getElementById('reason');         // The specific reason textarea

const myLeavesList = document.getElementById('my-leaves-list');
const pendingApprovalsCard = document.getElementById('pending-approvals-card');
const pendingApprovalsList = document.getElementById('pending-approvals-list');

let currentUser = null; // Will store user {id, name, email, role} and token

// --- Utility Functions ---
function showLoading() {
    loadingSpinner.classList.remove('hidden');
}

function hideLoading() {
    loadingSpinner.classList.add('hidden');
}

function showAuthMessage(message, isError = true) {
    authMessage.textContent = message;
    authMessage.className = `text-center text-sm mt-4 ${isError ? 'text-red-500' : 'text-green-500'}`;
}

function showApplyLeaveMessage(message, isError = true) {
    applyLeaveMessage.textContent = message;
    applyLeaveMessage.className = `text-center text-sm mt-2 ${isError ? 'text-red-500' : 'text-green-500'}`;
}

function clearMessages() {
    authMessage.textContent = '';
    applyLeaveMessage.textContent = '';
}

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return token ? {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    } : { 'Content-Type': 'application/json' };
}

function checkAuthenticationStatus() {
    const token = localStorage.getItem('token');
    const userString = localStorage.getItem('user');

    if (token && userString) {
        try {
            currentUser = JSON.parse(userString);
            updateUIForLoggedInUser();
            // Re-fetch data for the logged-in user
            loadMyLeaves();
            if (currentUser.role === 'teacher' || currentUser.role === 'admin') {
                loadPendingApprovals();
                pendingApprovalsCard.classList.remove('hidden');
            } else {
                pendingApprovalsCard.classList.add('hidden');
            }
        } catch (e) {
            console.error("Error parsing user data from localStorage:", e);
            logoutUser(); // Clear invalid data
        }
    } else {
        updateUIForLoggedOutUser();
    }
}

function updateUIForLoggedInUser() {
    userInfoSpan.textContent = `Logged in as: ${currentUser.name} (${currentUser.role})`;
    authSection.classList.add('hidden');
    dashboardSection.classList.remove('hidden');
}

function updateUIForLoggedOutUser() {
    currentUser = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    authSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
    clearMessages();
    loginForm.reset();
    registerForm.reset();
    myLeavesList.innerHTML = '<p class="text-gray-600">No leave applications found.</p>';
    pendingApprovalsList.innerHTML = '<p class="text-gray-600">No pending leave applications for approval.</p>';
    pendingApprovalsCard.classList.add('hidden');
}

// --- Authentication Logic ---

// Toggle between Login and Register forms
toggleAuthModeBtn.addEventListener('click', () => {
    loginForm.classList.toggle('hidden');
    registerForm.classList.toggle('hidden');
    if (loginForm.classList.contains('hidden')) {
        authTitle.textContent = 'Register';
        toggleAuthText.textContent = 'Already have an account?';
        toggleAuthModeBtn.textContent = 'Login';
    } else {
        authTitle.textContent = 'Login';
        toggleAuthText.textContent = 'Don\'t have an account?';
        toggleAuthModeBtn.textContent = 'Register';
    }
    clearMessages();
});

// User Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    showLoading();
    clearMessages();
    const email = loginForm['login-email'].value;
    const password = loginForm['login-password'].value;

    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            checkAuthenticationStatus(); // Update UI
        } else {
            showAuthMessage(data.message || 'Login failed.');
        }
    } catch (error) {
        console.error("Login Error:", error);
        showAuthMessage('Network error or server unavailable.');
    } finally {
        hideLoading();
    }
});

// User Registration
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    showLoading();
    clearMessages();
    const name = registerForm['register-name'].value;
    const email = registerForm['register-email'].value;
    const password = registerForm['register-password'].value;
    const role = registerForm['register-role'].value;

    if (!role) {
        showAuthMessage("Please select a role.");
        hideLoading();
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password, role })
        });
        const data = await response.json();

        if (response.ok) {
            showAuthMessage("Registration successful! You can now log in.", false);
            toggleAuthModeBtn.click(); // Switch to login form
        } else {
            showAuthMessage(data.message || 'Registration failed.');
        }
    } catch (error) {
        console.error("Registration Error:", error);
        showAuthMessage('Network error or server unavailable.');
    } finally {
        hideLoading();
    }
});

// User Logout
logoutBtn.addEventListener('click', () => {
    showLoading();
    logoutUser();
    hideLoading();
});

function logoutUser() {
    updateUIForLoggedOutUser();
}

// --- New: Calculate Days of Leave ---
function calculateDaysOfLeave() {
    const startDate = new Date(startDateInput.value);
    const endDate = new Date(endDateInput.value);

    // Check if dates are valid and start date is not after end date
    if (isNaN(startDate) || isNaN(endDate) || startDate > endDate) {
        daysOfLeaveDisplay.classList.add('hidden');
        calculatedDaysSpan.textContent = '0';
        return;
    }

    // Calculate difference in milliseconds
    const diffTime = Math.abs(endDate.getTime() - startDate.getTime());
    // Convert to days (add 1 because leave is inclusive of start and end date)
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;

    calculatedDaysSpan.textContent = diffDays;
    daysOfLeaveDisplay.classList.remove('hidden');
}

startDateInput.addEventListener('change', calculateDaysOfLeave);
endDateInput.addEventListener('change', calculateDaysOfLeave);

// --- New: Handle Reason Category Change ---
reasonSelect.addEventListener('change', () => {
    if (reasonSelect.value === 'other') {
        reasonGroup.classList.remove('hidden');
        reasonInput.setAttribute('required', 'true'); // Make specific reason required
    } else {
        reasonGroup.classList.add('hidden');
        reasonInput.removeAttribute('required'); // Make specific reason not required
        reasonInput.value = ''; // Clear the textarea when 'Other' is not selected
    }
});


// --- Leave Application Logic ---

applyLeaveForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    showLoading();
    showApplyLeaveMessage(''); // Clear previous message

    if (!currentUser) {
        showApplyLeaveMessage("User not logged in. Please re-login.");
        hideLoading();
        return;
    }

    const leaveData = {
        leaveType: leaveTypeInput.value,
        startDate: startDateInput.value,
        endDate: endDateInput.value,
        // New logic for reason:
        reason: reasonSelect.value === 'other' ? reasonInput.value : reasonSelect.value
    };

    // Basic date validation
    if (new Date(leaveData.startDate) > new Date(leaveData.endDate)) {
        showApplyLeaveMessage("Start date cannot be after end date.", true);
        hideLoading();
        return;
    }

    // Validate reason if 'Other' is selected and specific reason is empty
    if (reasonSelect.value === 'other' && !reasonInput.value.trim()) {
        showApplyLeaveMessage("Please specify the reason when 'Other' is selected.", true);
        hideLoading();
        return;
    }

    // Validate if a reason category is selected
    if (!reasonSelect.value) {
        showApplyLeaveMessage("Please select a reason category.", true);
        hideLoading();
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/leaves`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(leaveData)
        });
        const data = await response.json();

        if (response.ok) {
            showApplyLeaveMessage("Leave application submitted successfully!", false);
            applyLeaveForm.reset();
            reasonSelect.value = ''; // Reset reason dropdown
            reasonInput.value = ''; // Clear specific reason
            reasonGroup.classList.add('hidden'); // Hide specific reason input
            daysOfLeaveDisplay.classList.add('hidden'); // Hide calculated days
            calculatedDaysSpan.textContent = '0'; // Reset calculated days
            loadMyLeaves(); // Reload user's leaves
        } else if (response.status === 401 || response.status === 403) {
            showApplyLeaveMessage(data.message || "Session expired. Please log in again.", true);
            logoutUser();
        } else {
            showApplyLeaveMessage(data.message || "Error submitting leave.", true);
        }
    } catch (error) {
        console.error("Error submitting leave:", error);
        showApplyLeaveMessage("Network error or server unavailable.", true);
    } finally {
        hideLoading();
    }
});


// --- Display My Leaves ---

function renderMyLeaves(leaves) {
    myLeavesList.innerHTML = ''; // Clear previous entries
    if (leaves.length === 0) {
        myLeavesList.innerHTML = '<p class="text-gray-600">No leave applications found.</p>';
        return;
    }
    leaves.forEach(leave => {
        const leaveItem = document.createElement('div');
        leaveItem.className = 'bg-gray-50 p-4 rounded-md shadow-sm border border-gray-200';
        leaveItem.innerHTML = `
            <p class="font-semibold">Type: <span class="text-indigo-700">${leave.leaveType}</span></p>
            <p>Dates: ${leave.startDate} to ${leave.endDate}</p>
            <p>Reason: ${leave.reason}</p>
            <p class="mt-2 font-bold">Status: <span class="${
                leave.status === 'Approved' ? 'text-green-600' :
                leave.status === 'Rejected' ? 'text-red-600' : 'text-yellow-600'
            }">${leave.status}</span></p>
            ${leave.status !== 'Pending' && leave.approverName ? `<p class="text-sm text-gray-500">Approved/Rejected by: ${leave.approverName} on ${new Date(leave.approvedAt).toLocaleDateString()}</p>` : ''}
            ${leave.approverRemarks ? `<p class="text-sm text-gray-500">Remarks: ${leave.approverRemarks}</p>` : ''}
        `;
        myLeavesList.appendChild(leaveItem);
    });
}

async function loadMyLeaves() {
    if (!currentUser) return; // Don't load if not logged in

    try {
        const response = await fetch(`${API_BASE_URL}/leaves/my`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        const data = await response.json();

        if (response.ok) {
            renderMyLeaves(data);
        } else if (response.status === 401 || response.status === 403) {
            alert(data.message || "Session expired. Please log in again.");
            logoutUser();
        } else {
            myLeavesList.innerHTML = `<p class="text-red-500">Error loading your leave applications: ${data.message || 'Server error'}</p>`;
        }
    } catch (error) {
        console.error("Error fetching my leaves:", error);
        myLeavesList.innerHTML = '<p class="text-red-500">Network error loading your leave applications.</p>';
    }
}


// --- Display Pending Approvals (Teacher/Admin) ---

function renderPendingApprovals(leaves) {
    pendingApprovalsList.innerHTML = ''; // Clear previous entries
    if (leaves.length === 0) {
        pendingApprovalsList.innerHTML = '<p class="text-gray-600">No pending leave applications for approval.</p>';
        return;
    }
    leaves.forEach(leave => {
        const leaveItem = document.createElement('div');
        leaveItem.className = 'bg-gray-50 p-4 rounded-md shadow-sm border border-gray-200';
        leaveItem.innerHTML = `
            <p class="font-semibold">Applicant: ${leave.applicantName} (${leave.applicantRole})</p>
            <p>Type: <span class="text-indigo-700">${leave.leaveType}</span></p>
            <p>Dates: ${leave.startDate} to ${leave.endDate}</p>
            <p>Reason: ${leave.reason}</p>
            <p class="text-sm text-gray-500">Submitted on: ${new Date(leave.submittedAt).toLocaleDateString()}</p>
            <div class="mt-4 flex space-x-2">
                <input type="text" id="remarks-${leave.id}" placeholder="Remarks (Optional)" class="flex-grow px-3 py-1 border border-gray-300 rounded-md text-sm">
                <button data-id="${leave.id}" data-status="Approved" class="approve-btn bg-green-500 text-white py-1 px-3 rounded-md hover:bg-green-600 text-sm">Approve</button>
                <button data-id="${leave.id}" data-status="Rejected" class="reject-btn bg-red-500 text-white py-1 px-3 rounded-md hover:bg-red-600 text-sm">Reject</button>
            </div>
        `;
        pendingApprovalsList.appendChild(leaveItem);
    });

    // Add event listeners for approve/reject buttons
    pendingApprovalsList.querySelectorAll('.approve-btn, .reject-btn').forEach(button => {
        button.addEventListener('click', handleLeaveAction);
    });
}

async function loadPendingApprovals() {
    if (!currentUser || (currentUser.role !== 'teacher' && currentUser.role !== 'admin')) {
        pendingApprovalsCard.classList.add('hidden'); // Hide if not authorized
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/leaves/pending`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        const data = await response.json();

        if (response.ok) {
            renderPendingApprovals(data);
        } else if (response.status === 401 || response.status === 403) {
            alert(data.message || "Authorization failed. Please log in again.");
            logoutUser();
        } else {
            pendingApprovalsList.innerHTML = `<p class="text-red-500">Error loading pending approvals: ${data.message || 'Server error'}</p>`;
        }
    } catch (error) {
        console.error("Error fetching pending approvals:", error);
        pendingApprovalsList.innerHTML = '<p class="text-red-500">Network error loading pending approvals.</p>';
    }
}

// Initial check on page load
document.addEventListener('DOMContentLoaded', checkAuthenticationStatus);