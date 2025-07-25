import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';

const NetworkGraph = ({ data, onNodeClick, selectedNode }) => {
    const svgRef = useRef(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

    useEffect(() => {
        const updateDimensions = () => {
            const container = svgRef.current?.parentElement;
            if (container) {
                setDimensions({
                    width: container.clientWidth,
                    height: container.clientHeight
                });
            }
        };

        updateDimensions();
        window.addEventListener('resize', updateDimensions);
        return () => window.removeEventListener('resize', updateDimensions);
    }, []);

    useEffect(() => {
        if (!data.nodes.length) return;

        const svg = d3.select(svgRef.current);
        svg.selectAll("*").remove();

        const { width, height } = dimensions;
        
        // Set up zoom
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                container.attr('transform', event.transform);
            });

        svg.call(zoom);

        const container = svg.append('g');

        // Color scale based on risk level
        const colorScale = d3.scaleOrdinal()
            .domain(['low', 'medium', 'high', 'critical'])
            .range(['#10B981', '#F59E0B', '#EF4444', '#DC2626']);

        // Size scale based on risk score
        const sizeScale = d3.scaleLinear()
            .domain(d3.extent(data.nodes, d => d.riskScore))
            .range([8, 25]);

        // Create simulation
        const simulation = d3.forceSimulation(data.nodes)
            .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(d => sizeScale(d.riskScore) + 5));

        // Add links
        const link = container.append('g')
            .selectAll('line')
            .data(data.links)
            .join('line')
            .attr('stroke', '#999')
            .attr('stroke-opacity', 0.6)
            .attr('stroke-width', 2);

        // Add nodes
        const node = container.append('g')
            .selectAll('circle')
            .data(data.nodes)
            .join('circle')
            .attr('r', d => sizeScale(d.riskScore))
            .attr('fill', d => colorScale(d.riskLevel))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));

        // Add labels
        const label = container.append('g')
            .selectAll('text')
            .data(data.nodes)
            .join('text')
            .text(d => d.name)
            .attr('font-size', 12)
            .attr('font-family', 'Arial, sans-serif')
            .attr('text-anchor', 'middle')
            .attr('dy', '.35em')
            .style('pointer-events', 'none')
            .style('user-select', 'none');

        // Node click handler
        node.on('click', (event, d) => {
            event.stopPropagation();
            onNodeClick(d);
        });

        // Highlight selected node
        if (selectedNode) {
            node
                .attr('stroke', d => d.id === selectedNode.id ? '#3B82F6' : '#fff')
                .attr('stroke-width', d => d.id === selectedNode.id ? 4 : 2);
        }

        // Simulation tick
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);

            label
                .attr('x', d => d.x)
                .attr('y', d => d.y - sizeScale(d.riskScore) - 5);
        });

        // Drag functions
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        // Add legend
        const legend = svg.append('g')
            .attr('transform', 'translate(20, 20)');

        const legendData = [
            { color: '#10B981', label: 'Low Risk' },
            { color: '#F59E0B', label: 'Medium Risk' },
            { color: '#EF4444', label: 'High Risk' },
            { color: '#DC2626', label: 'Critical Risk' }
        ];

        const legendItems = legend.selectAll('.legend-item')
            .data(legendData)
            .join('g')
            .attr('class', 'legend-item')
            .attr('transform', (d, i) => `translate(0, ${i * 25})`);

        legendItems.append('circle')
            .attr('r', 8)
            .attr('fill', d => d.color);

        legendItems.append('text')
            .attr('x', 20)
            .attr('y', 5)
            .text(d => d.label)
            .attr('font-size', 14)
            .attr('font-family', 'Arial, sans-serif');

    }, [data, dimensions, selectedNode, onNodeClick]);

    return (
        <div className="w-full h-full">
            <svg
                ref={svgRef}
                width={dimensions.width}
                height={dimensions.height}
                style={{ border: '1px solid #e2e8f0' }}
            />
        </div>
    );
};

export default NetworkGraph;
