const svg = d3.select("#net");

const nodes = [
  "sm1","sm2","sm3","sm4","sm5",
  "regS1","reg1","sp","so",
  "reg2","regS2","sm6","sm7","sm8","sm9","sm10"
];

const links = [
  ["sm1","regS1"],["sm2","regS1"],["sm3","regS1"],["sm4","regS1"],["sm5","regS1"],
  ["regS1","reg1"],["reg1","sp"],
  ["sp","so"],
  ["reg2","sp"],["regS2","reg2"],
  ["sm6","regS2"],["sm7","regS2"],["sm8","regS2"],["sm9","regS2"],["sm10","regS2"]
];

const pos = {
  sm1:[100,80], sm2:[100,120], sm3:[100,160], sm4:[100,200], sm5:[100,240],
  regS1:[300,160], reg1:[450,160],
  sp:[650,160], so:[850,160],
  reg2:[450,360], regS2:[300,360],
  sm6:[100,300], sm7:[100,340], sm8:[100,380], sm9:[100,420], sm10:[100,460]
};

// Draw links
links.forEach(l => {
  svg.append("line")
     .attr("x1",pos[l[0]][0]).attr("y1",pos[l[0]][1])
     .attr("x2",pos[l[1]][0]).attr("y2",pos[l[1]][1]);
});

// Draw nodes
nodes.forEach(n => {
  svg.append("circle")
     .attr("cx",pos[n][0]).attr("cy",pos[n][1]).attr("r",20);
  svg.append("text")
     .attr("x",pos[n][0]-15).attr("y",pos[n][1]+35)
     .text(n);
});

// Animate packet
function animate(from, to, attack=false) {
  svg.append("circle")
     .attr("r",6)
     .attr("class", attack ? "attack" : "packet")
     .attr("cx",pos[from][0])
     .attr("cy",pos[from][1])
     .transition().duration(800)
     .attr("cx",pos[to][0])
     .attr("cy",pos[to][1])
     .remove();
}

const ws = new WebSocket("ws://localhost:3000");

ws.onmessage = e => {
  const ev = JSON.parse(e.data);
  animate(ev.from, ev.to, ev.attack);
};
