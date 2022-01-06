const displayCountersValue = () => {
    const password = document.getElementById('password').value;
    document.getElementById('quality-counter').innerHTML = calculateEntropy(password);
};

const calculateEntropy = (text) => {
    const signs = {};
    let entropy = 0;

    for (let i = 0; i < text.length; i++) {
        let char = text[i];

        if (Object.keys(signs).includes(char)) signs[char] += 1;
        else signs[char] = 1;
    }

    for (const [char, count] of Object.entries(signs)) {
        let p = count / text.length;
        entropy -= p * Math.log2(p);
    }

    return entropy;
};
