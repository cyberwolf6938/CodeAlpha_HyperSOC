const networkCanvas =
document.getElementById("networkCanvas");

if (!networkCanvas) {
console.error("networkCanvas not found");
}

const netCtx =
networkCanvas ?
networkCanvas.getContext("2d") :
null;

// ====================================
// GLOBALS
// ====================================

let vehicles = [];

let sourceNodes = {};
let destinationNodes = {};

let threatRoutes = [];

// ====================================
// BUILD NODES
// ====================================

function buildNodes(packets){


sourceNodes = {};
destinationNodes = {};

let srcs = [...new Set(
    packets.map(p => p.src)
)].slice(0,10);

let dsts = [...new Set(
    packets.map(p => p.dst)
)].slice(0,10);

srcs.forEach((ip,index)=>{

    sourceNodes[ip] = {

        x:100,
        y:50 + index * 40

    };

});

dsts.forEach((ip,index)=>{

    destinationNodes[ip] = {

        x:1100,
        y:50 + index * 40

    };

});


}

// ====================================
// PACKET VEHICLE
// ====================================

function addPacket(packet){


let src =
sourceNodes[packet.src];

let dst =
destinationNodes[packet.dst];

if(!src || !dst)
    return;

let color = "#00ff00";
let size = 4;

if(packet.size > 500){

    color = "#00ffff";
    size = 6;

}

if(packet.size > 1200){

    color = "#ff9900";
    size = 10;

}

vehicles.push({

    x: src.x,
    y: src.y,

    targetX: dst.x,
    targetY: dst.y,

    color: color,
    size: size,

    speed: 0.02

});


}

// ====================================
// THREAT ROUTES
// ====================================

function addThreatRoute(
src,
dst,
severity
){


threatRoutes.push({

    src: src,
    dst: dst,
    severity: severity,
    created: Date.now()

});


}

function getSeverityColor(severity){

if(severity === "LOW")
    return "#00ff00";

if(severity === "MEDIUM")
    return "#ffff00";

if(severity === "HIGH")
    return "#ff8800";

if(severity === "CRITICAL")
    return "#ff0000";

return "#ffffff";

}

// ====================================
// DRAW NETWORK
// ====================================

function drawNetwork(){

if(!netCtx)
    return;

netCtx.clearRect(
    0,
    0,
    networkCanvas.width,
    networkCanvas.height
);

// ----------------
// THREAT ROUTES
// ----------------

threatRoutes.forEach(route=>{

    let src =
    sourceNodes[route.src];

    let dst =
    destinationNodes[route.dst];

    if(!src || !dst)
        return;

    netCtx.beginPath();

    netCtx.strokeStyle =
    getSeverityColor(
        route.severity
    );

    netCtx.lineWidth = 4;

    netCtx.moveTo(
        src.x,
        src.y
    );

    netCtx.lineTo(
        dst.x,
        dst.y
    );

    netCtx.stroke();

});

// ----------------
// SOURCE NODES
// ----------------

netCtx.fillStyle =
"#00ff88";

Object.entries(sourceNodes)
.forEach(([ip,node])=>{

    netCtx.beginPath();

    netCtx.arc(
        node.x,
        node.y,
        8,
        0,
        Math.PI * 2
    );

    netCtx.fill();

    netCtx.fillText(
        ip,
        node.x + 15,
        node.y + 5
    );

});

// ----------------
// DESTINATION NODES
// ----------------

Object.entries(destinationNodes)
.forEach(([ip,node])=>{

    netCtx.beginPath();

    netCtx.arc(
        node.x,
        node.y,
        8,
        0,
        Math.PI * 2
    );

    netCtx.fill();

    netCtx.fillText(
        ip,
        node.x - 120,
        node.y + 5
    );

});

}

// ====================================
// ANIMATION LOOP
// ====================================

function animatePackets(){

drawNetwork();

vehicles.forEach(v=>{

    v.x +=
    (v.targetX - v.x)
    * v.speed;

    v.y +=
    (v.targetY - v.y)
    * v.speed;

    netCtx.beginPath();

    netCtx.fillStyle =
    v.color;

    netCtx.arc(
        v.x,
        v.y,
        v.size,
        0,
        Math.PI * 2
    );

    netCtx.fill();

});

vehicles =
vehicles.filter(v=>{

    return Math.abs(
        v.targetX - v.x
    ) > 5;

});

threatRoutes =
threatRoutes.filter(route=>{

    return (
        Date.now()
        -
        route.created
    ) < 10000;

});

requestAnimationFrame(
    animatePackets
);

}

// ====================================
// START ENGINE
// ====================================

if(netCtx){

animatePackets();

}
