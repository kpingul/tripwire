const API_RECORDS = "http://127.0.0.1:8090/api/records"

//create XMLHttpRequest object
const xhr = new XMLHttpRequest()

//open a get request with the remote server URL
xhr.open("GET", API_RECORDS)

//send the Http request
xhr.send()

//EVENT HANDLERS
//triggered when the response is completed
xhr.onload = function() {
        if (xhr.status === 200) {
                //parse JSON datax`x
                data = JSON.parse(xhr.responseText)
                console.log(data)

                if ( data.length > 0 ) {
                        var     nodesObj = {},
                                nodes = [],
                                edges = [];

                        data.forEach( (node, idx) => {
                                if ( idx == 0 ) { 
                                        nodesObj[node.AccountDomain] = {
                                                data: {
                                                        id: node.AccountDomain,
                                                        label: node.AccountDomain,
                                                        shape: "diamond"
                                                }
                                        }
                                        nodes.push(
                                                {
                                                        data: {
                                                                id: node.AccountDomain,
                                                                label: node.AccountDomain,
                                                                shape: "diamond"
                                                        }
                                                }
                                        )   
                                        nodesObj[node.AccountName] = {
                                                data: {
                                                        id: node.AccountName,
                                                        label: node.AccountName,
                                                        shape: "circle"
                                                }
                                        }
                                        nodes.push(
                                                {
                                                        data: {
                                                                id: node.AccountName,
                                                                label: node.AccountName,
                                                                shape: "circle"
                                                        }
                                                }
                                        )    
                                        nodesObj[node.ObjectName] = {
                                                data: {
                                                        id: node.ObjectName,
                                                        label: node.ObjectName,
                                                        shape: "tag"
                                                }
                                        }
                                        nodes.push(
                                                {
                                                        data: {
                                                                id: node.ObjectName,
                                                                label: node.ObjectName,
                                                                shape: "tag"
                                                        }
                                                }
                                        )

                                        //need to refactor this similar to above..
                                        edges.push({
                                                data: {
                                                        id: node.ID + "a",
                                                        weight: 1,
                                                        source: node.AccountDomain,
                                                        target: node.AccountName,
                                                        label: "",
                                                }
                                        })
                                }
                                if ( node.EventID == "4663" &&  !nodesObj.hasOwnProperty(node.ProcessName) ) {
                                        nodesObj[node.ProcessName] = {
                                                data: {
                                                        id: node.ProcessName,
                                                        label: node.ProcessName,
                                                        shape: "square"
                                                }
                                        }
                                        nodes.push(
                                                {
                                                        data: {
                                                                id: node.ProcessName,
                                                                label: node.ProcessName,
                                                                shape: "square"
                                                        }
                                                }
                                        )

                                        //user to process
                                        edges.push({
                                                data: {
                                                        id: node.ID + "b",
                                                        weight: 1,
                                                        source: node.AccountName,
                                                        target: node.ProcessName,
                                                        label: "",
                                                }
                                        })                                        


                                        //process to file

                                        edges.push({
                                                data: {
                                                        id: node.ID + "c",
                                                        weight: 1,
                                                        source: node.ProcessName,
                                                        target: node.ObjectName,
                                                        label: "",
                                                }
                                        })     
                                        console.log("YO")
                                        console.log(nodes)
                                        console.log(edges)

                                }


                        })
                   
                        var cy = cytoscape({
                                container: document.getElementById('cy'),
                                boxSelectionEnabled: false,
                                autounselectify: true,
                                style:  cytoscape.stylesheet()
                                        .selector('node')
                                        .style({
                                                'content': 'data(label)',
                                                'width': '20',
                                                'height': '20',
                                                // 'shape': 'data(shape)',
                                                'font-size': '11',
                                                "text-valign": "top",
                                                "text-halign": "center"
                                        })
                                        .selector('edge')
                                        .style({
                                                'content': 'data(label)',
                                                'font-size': '8',
                                                'curve-style': 'bezier',
                                                 "edge-text-rotation": "autorotate",
                                                'target-arrow-shape': 'triangle',
                                                'width': 2,
                                                'line-color': '#ddd',
                                                'target-arrow-color': '#ddd'
                                        })
                                        .selector('.highlighted')
                                        .style({
                                                'background-color': '#D2042D',
                                                'line-color': '#B0C4DE ',
                                                'target-arrow-color': '#B0C4DE ',
                                                'transition-property': 'background-color, line-color, target-arrow-color',
                                                'transition-duration': '0.5s'
                                        }),
                                        elements: {
                                                nodes: nodes,
                                                edges: edges
                                        },

                                        layout: {
                                                name: 'breadthfirst',
                                                directed: true,
                                                padding: 10
                                        }
                                });

                        var bfs = cy.elements().bfs('#a', function(){}, true);

                        var i = 0;
                        var highlightNextEle = function(){
                                if( i < bfs.path.length ){
                                        bfs.path[i].addClass('highlighted');
                                        i++;
                                        setTimeout(highlightNextEle, 1000);
                                }
                        };

                        
                        // kick off first highlight
                        highlightNextEle();
                }
        } else if (xhr.status === 404) {
                console.log("No records found")
        }
}

//triggered when a network-level error occurs with the request
xhr.onerror = function() {
        console.log("Network error occurred")
}

