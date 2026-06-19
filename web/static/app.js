let protocolChart = null;
let attackerChart = null;

const socket = io();

socket.on("connect", () => {
    console.log("Connected to HyperSOC");
});

socket.on("dashboard_update", (d) => {
    renderDashboard(d);
});

function renderDashboard(d) {
    let socStatus =
     document.getElementById(
        "socStatus"
    );

     if(socStatus){

    let level =
        "MONITORING";

    let color =
    "#00ff00";

    if(d.threat_score > 10){

        level =
        "ELEVATED";

        color =
        "#ffff00";
    }

    if(d.threat_score > 25){

        level =
        "HIGH RISK";

        color =
        "#ff8800";
    }

    if(d.threat_score > 50){

        level =
        "CRITICAL";

        color =
        "#ff0000";
    }

    socStatus.innerHTML =
    `<h3 style="color:${color}">
        ${level}
    </h3>`;
}
setInterval(()=>{

    let clock =
    document.getElementById(
        "clock"
    );

    if(clock){

        clock.innerText =
        new Date()
        .toLocaleString();
    }

},1000);

    // Main Stats
    document.getElementById("packets").innerText =
        d.packets || 0;

    let scoreBox =
document.getElementById(
    "score"
);

if(scoreBox){

    scoreBox.innerText =
    d.threat_score || 0;

    if(
        d.threat_score > 50
    ){

        scoreBox.style.color =
        "red";

    }else if(
        d.threat_score > 25
    ){

        scoreBox.style.color =
        "orange";

    }else{

        scoreBox.style.color =
        "lime";
    }
}

    let alertBox =
document.getElementById(
    "alerts"
);

if(alertBox){

    alertBox.innerText =
    d.alerts || 0;

    if(d.alerts > 20){

        alertBox.style.color =
        "red";

    }else if(
        d.alerts > 10
    ){

        alertBox.style.color =
        "orange";

    }else{

        alertBox.style.color =
        "lime";

    }
}
    // Protocol Chart
    let protocols = d.protocols || {};

    let protocolCanvas =
        document.getElementById("protocolChart");

    if (protocolCanvas) {

        if (!protocolChart) {

            protocolChart =
                new Chart(protocolCanvas, {

                    type: "doughnut",

                    data: {
                        labels: Object.keys(protocols),

                        datasets:[{
    data:Object.values(protocols),

    backgroundColor:[
        "#00ff88", // TCP
        "#00bfff", // UDP
        "#ff9900", // OTHER
        "#ff4444",
        "#aa66ff"
    ],

    borderColor:"#111",
    borderWidth:2
}]
                    },

                    options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            labels: {
                color: "#ffffff"
            }
        }
    }
}

                });

        } else {

            protocolChart.data.labels =
                Object.keys(protocols);

            protocolChart.data.datasets[0].data =
                Object.values(protocols);

            protocolChart.update();
        }
    }

    // Top Attackers List
    let attackers =
        document.getElementById("attackers");

    if (attackers) {

        attackers.innerHTML = "";

        Object.entries(d.attackers || {})
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .forEach(x => {

                attackers.innerHTML +=
                    `<li>${x[0]} (${x[1]})</li>`;

            });
    }

    // Attacker Chart
    let attackerData =
        Object.entries(d.attackers || {})
        .sort((a,b)=>b[1]-a[1])
        .slice(0,5);

    let attackerLabels =
        attackerData.map(x => x[0]);

    let attackerScores =
        attackerData.map(x => x[1]);

    let attackerCanvas =
        document.getElementById("attackerChart");

    if(attackerCanvas){

        if(!attackerChart){

            attackerChart =
                new Chart(attackerCanvas,{

                    type:"bar",

                    data:{
                        labels: attackerLabels,

                        datasets:[{
                            label:"Threat Score",
                            data: attackerScores
                        }]
                    },

                    options:{
    responsive:true,
    maintainAspectRatio:false,

    plugins:{
        legend:{
            display:false
        }
    },

    scales:{
        y:{
            beginAtZero:true
        }
    }
}

                });

        } else {

            attackerChart.data.labels =
                attackerLabels;

            attackerChart.data.datasets[0].data =
                attackerScores;

            attackerChart.update();
        }
    }

    // Top Talkers
    let talkers =
        document.getElementById("talkers");

    if (talkers) {

        talkers.innerHTML = "";

        Object.entries(d.top_talkers || {})
            .forEach(x => {

                talkers.innerHTML +=
                    `<li>${x[0]} (${x[1]})</li>`;

            });
    }
   if(typeof threatRoutes !== "undefined"){

    threatRoutes = [];

    (d.recent_alerts || [])
    .forEach(alert=>{

        if(alert.includes("PortScan")){

            addThreatRoute(
                "192.168.1.1",
                "104.18.32.47",
                "HIGH"
            );

        }

    });

}

    // Recent Alerts
    let recent =
        document.getElementById("recent");

    if (recent) {

        recent.innerHTML = "";

        (d.recent_alerts || []).forEach(a => {

            recent.innerHTML +=
                `<li>${a}</li>`;

        });
    }

    // Threat Categories
    let categories =
        document.getElementById("categories");

    if (categories) {

        categories.innerHTML = "";

        Object.entries(
            d.threat_categories || {}
        ).forEach(x => {

            categories.innerHTML +=
                `<li>${x[0]} : ${x[1]}</li>`;

        });
    }

    // Live Traffic
    let traffic =
        document.getElementById("traffic");

    if (traffic) {

        traffic.innerHTML = "";

        (d.live_packets || [])
            .slice(-100)
            .forEach(p => {

                traffic.innerHTML += `
<tr>
<td>${p.proto}</td>
<td>${p.src}</td>
<td>→</td>
<td>${p.dst}</td>
<td>${p.size}</td>
</tr>`;
            });
    }

    // Risk Meter
    let meter =
        document.getElementById("riskMeter");

    if (meter) {

        meter.value =
            Math.min(
                d.threat_score || 0,
                100
            );
    }

    // Evidence
    let evidence =
document.getElementById(
    "evidence"
);

     if(evidence){

    let count =
        d.evidence || 0;

    if(count === 0){

    evidence.innerHTML =
    "STATUS: CLEAN";

}else{

    evidence.innerHTML =
    `STATUS: ${count} Evidence Files Captured`;

}
}
    if(typeof buildNodes !== "undefined"){

    buildNodes(
        d.live_packets || []
    );

    (d.live_packets || [])
    .slice(-20)
    .forEach(packet=>{

   if(typeof addPacket === "function"){
    addPacket(packet);
}

    });
}
     let timeline =
        document.getElementById(
    "timeline"
);

if(timeline){

    timeline.innerHTML = "";

    (d.recent_alerts || [])
    .slice(0,10)
    .forEach(alert=>{

        let now =
        new Date()
        .toLocaleTimeString();

        timeline.innerHTML +=
        `<li>
            [${now}]
            ${alert}
        </li>`;

    });
}
let summary =
document.getElementById(
    "analystSummary"
);

if(summary){

    let status =
    "NORMAL";

    if(
        d.threat_score > 10
    ){
        status = "ELEVATED";
    }

    if(
        d.threat_score > 25
    ){
        status = "HIGH RISK";
    }

    if(
        d.threat_score > 50
    ){
        status = "CRITICAL";
    }

    summary.innerHTML = `
    <b>Status:</b> ${status}<br>
    <b>Packets:</b> ${d.packets}<br>
    <b>Alerts:</b> ${d.alerts}<br>
    <b>Attackers:</b>
    ${
        Object.keys(
            d.attackers || {}
        ).length
    }
    `;
}
    let mitre =
        document.getElementById(
    "mitreList"
);

     if(mitre){

        mitre.innerHTML = "";

    (d.mitre || [])
    .forEach(m => {

        mitre.innerHTML += `
<li>
<b>${m.technique}</b>
<br>
${m.name}
(${m.count})
</li>
`;

    });

}
}

async function updateDashboard() {

    try {

        let r =
            await fetch("/api/dashboard");

        let d =
            await r.json();

        renderDashboard(d);

        let severity =
        document.getElementById(
            "severityList"
        );

        if(severity){

            severity.innerHTML = "";

            Object.entries(
                d.severity || {}
            )
            .forEach(x => {

                let color = "white";

                if(x[0] === "LOW")
                    color = "lime";

                else if(x[0] === "MEDIUM")
                    color = "yellow";

                else if(x[0] === "HIGH")
                    color = "orange";

                else if(x[0] === "CRITICAL")
                    color = "red";

                severity.innerHTML +=
                `<li style="color:${color}">
                    ${x[0]} : ${x[1]}
                </li>`;
            });
        }

    } catch(err) {

        console.error(
            "Dashboard Error:",
            err
        );

    }
}
async function exportReport(){

    let r =
    await fetch(
        "/api/dashboard"
    );

    let d =
    await r.json();

    let blob =
    new Blob(
        [
            JSON.stringify(
                d,
                null,
                4
            )
        ],
        {
            type:
            "application/json"
        }
    );

    let url =
    URL.createObjectURL(
        blob
    );

    let a =
    document.createElement(
        "a"
    );

    a.href = url;

    a.download =
    "HyperSOC_Report.json";

    a.click();
}
setInterval(updateDashboard, 1000);
updateDashboard();