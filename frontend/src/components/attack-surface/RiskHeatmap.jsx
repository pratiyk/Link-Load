import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const RiskHeatmap = ({ assets }) => {
    const svgRef = useRef(null);

    useEffect(() => {
        if (!assets.length) return;

        const svg = d3.select(svgRef.current);
        svg.selectAll("*").remove();

        const margin = { top: 20, right: 20, bottom: 30, left: 40 };
        const width = 350 - margin.left - margin.right;
        const height = 200 - margin.bottom - margin.top;

        const g = svg.append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        // Process data - group by risk level
        const riskCounts = assets.reduce((acc, asset) => {
            acc[asset.risk_level] = (acc[asset.risk_level] || 0) + 1;
            return acc;
        }, {});

        const data = Object.entries(riskCounts).map(([level, count]) => ({
            level,
            count,
            percentage: (count / assets.length) * 100
        }));

        // Color scale
        const colorScale = d3.scaleOrdinal()
            .domain(['low', 'medium', 'high', 'critical'])
            .range(['#10B981', '#F59E0B', '#EF4444', '#DC2626']);

        // Scales
        const xScale = d3.scaleBand()
            .domain(['low', 'medium', 'high', 'critical'])
            .range([0, width])
            .padding(0.1);

        const yScale = d3.scaleLinear()
            .domain([0, d3.max(data, d => d.count)])
            .range([height, 0]);

        // Add bars
        g.selectAll('.bar')
            .data(data)
            .join('rect')
            .attr('class', 'bar')
            .attr('x', d => xScale(d.level))
            .attr('width', xScale.bandwidth())
            .attr('y', d => yScale(d.count))
            .attr('height', d => height - yScale(d.count))
            .attr('fill', d => colorScale(d.level))
            .attr('opacity', 0.8);

        // Add labels
        g.selectAll('.label')
            .data(data)
            .join('text')
            .attr('class', 'label')
            .attr('x', d => xScale(d.level) + xScale.bandwidth() / 2)
            .attr('y', d => yScale(d.count) - 5)
            .attr('text-anchor', 'middle')
            .attr('font-size', 12)
            .attr('font-weight', 'bold')
            .text(d => d.count);

        // Add x-axis
        g.append('g')
            .attr('transform', `translate(0,${height})`)
            .call(d3.axisBottom(xScale))
            .selectAll('text')
            .style('text-transform', 'capitalize');

        // Add y-axis
        g.append('g')
            .call(d3.axisLeft(yScale));

        // Add title
        svg.append('text')
            .attr('x', width / 2 + margin.left)
            .attr('y', 15)
            .attr('text-anchor', 'middle')
            .attr('font-size', 14)
            .attr('font-weight', 'bold')
            .text('Risk Distribution');

    }, [assets]);

    return (
        <div className="p-4">
            <svg
                ref={svgRef}
                width={350}
                height={240}
                className="w-full h-full"
            />
        </div>
    );
};

export default RiskHeatmap;
