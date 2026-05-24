const steps = ["s0", "s1", "s2", "s3", "s4"];
const labels = [
  "Connecting to daemon...",
  "Loading ClamAV engine...",
  "Loading signatures...",
  "Initializing ARGUS heuristics...",
  "Preparing real-time monitoring...",
];
let current = 0;

const bg = document.querySelector(".bg");
if (bg) {
  bg.addEventListener("error", () => {
    bg.style.display = "none";
  });
}

function advance() {
  if (current >= steps.length) return;
  const currentStep = document.getElementById(steps[current]);
  if (currentStep) currentStep.className = "step done";
  current += 1;
  const status = document.getElementById("status");
  if (current < steps.length) {
    const nextStep = document.getElementById(steps[current]);
    if (nextStep) nextStep.className = "step active";
    if (status) status.textContent = labels[current];
  } else if (status) {
    status.textContent = "Ready";
  }
}

setTimeout(advance, 1500);
setTimeout(advance, 3500);
setTimeout(advance, 5500);
setTimeout(advance, 7500);
setTimeout(advance, 9500);
setTimeout(() => {
  const status = document.getElementById("status");
  if (status) status.textContent = "Almost ready...";
}, 11000);
