(function () {
    const t = (key) => window.CtbI18n?.t(key) || key;

    const patternInput = document.getElementById('patternInput');
    const testInput = document.getElementById('testInput');
    const regexError = document.getElementById('regexError');
    const matchInfo = document.getElementById('matchInfo');
    const matchCountEl = document.getElementById('matchCount');
    const highlightOutput = document.getElementById('highlightOutput');
    const matchDetails = document.getElementById('matchDetails');
    const matchList = document.getElementById('matchList');

    const flagG = document.getElementById('flagG');
    const flagI = document.getElementById('flagI');
    const flagM = document.getElementById('flagM');
    const flagS = document.getElementById('flagS');

    function getFlags() {
        let f = '';
        if (flagG.checked) f += 'g';
        if (flagI.checked) f += 'i';
        if (flagM.checked) f += 'm';
        if (flagS.checked) f += 's';
        return f;
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function runTest() {
        const pattern = patternInput.value;
        const text = testInput.value;

        regexError.style.display = 'none';
        matchInfo.style.display = 'none';
        matchDetails.style.display = 'none';
        highlightOutput.innerHTML = '';
        matchList.innerHTML = '';

        if (!pattern || !text) {
            if (text && !pattern) {
                highlightOutput.textContent = text;
            }
            return;
        }

        let regex;
        try {
            regex = new RegExp(pattern, getFlags());
        } catch (e) {
            regexError.textContent = t('tool.regex.invalid') + ' ' + e.message;
            regexError.style.display = 'block';
            highlightOutput.textContent = text;
            return;
        }

        // Find all matches
        const matches = [];
        if (regex.global) {
            let m;
            while ((m = regex.exec(text)) !== null) {
                matches.push({ value: m[0], index: m.index, groups: m.slice(1) });
                if (m[0].length === 0) { regex.lastIndex++; }
            }
        } else {
            const m = regex.exec(text);
            if (m) {
                matches.push({ value: m[0], index: m.index, groups: m.slice(1) });
            }
        }

        // Update count
        matchCountEl.textContent = matches.length;
        matchInfo.style.display = 'flex';

        // Highlight text
        if (matches.length > 0) {
            let html = '';
            let lastIndex = 0;

            // Sort by index
            matches.sort((a, b) => a.index - b.index);

            for (const match of matches) {
                // Text before match
                html += escapeHtml(text.slice(lastIndex, match.index));
                // Highlighted match
                html += `<span class="match-highlight">${escapeHtml(match.value)}</span>`;
                lastIndex = match.index + match.value.length;
            }
            // Remaining text
            html += escapeHtml(text.slice(lastIndex));
            highlightOutput.innerHTML = html;

            // Match details
            matchDetails.style.display = 'block';
            matches.forEach((match, i) => {
                const item = document.createElement('div');
                item.className = 'match-item';

                let groupsHtml = '';
                if (match.groups.length > 0) {
                    groupsHtml = `<div class="match-groups">${match.groups.map((g, gi) =>
                        `<div class="match-group"><strong>$${gi + 1}:</strong> ${escapeHtml(g || '')}</div>`
                    ).join('')}</div>`;
                }

                item.innerHTML = `
                    <span class="match-index">${i + 1}</span>
                    <span class="match-value">${escapeHtml(match.value)}</span>
                    ${groupsHtml}
                    <span class="match-position">[${match.index}:${match.index + match.value.length}]</span>
                `;
                matchList.appendChild(item);
            });
        } else {
            highlightOutput.textContent = text;
        }
    }

    // Preset chips
    document.querySelectorAll('.preset-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            patternInput.value = chip.dataset.pattern;
            runTest();
        });
    });

    // Real-time testing
    patternInput.addEventListener('input', runTest);
    testInput.addEventListener('input', runTest);
    [flagG, flagI, flagM, flagS].forEach(f => f.addEventListener('change', runTest));
})();
