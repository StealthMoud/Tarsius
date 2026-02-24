// concurent task runner

// run async tasks with a concurency limit
// items = array of things to process
// fn = async function that processes each item
// limit = how many to run at once
export async function pMap(items, fn, limit = 10) {
    const results = [];
    let index = 0;

    async function worker() {
        while (index < items.length) {
            const i = index++;
            results[i] = await fn(items[i], i);
        }
    }

    const workers = [];
    for (let i = 0; i < Math.min(limit, items.length); i++) {
        workers.push(worker());
    }

    await Promise.all(workers);
    return results;
}

// run async tasks concurently but with a callback for each result
// good for when you want to process results as they come in
export async function pForEach(items, fn, limit = 10) {
    let index = 0;

    async function worker() {
        while (index < items.length) {
            const i = index++;
            if (i < items.length) {
                await fn(items[i], i);
            }
        }
    }

    const workers = [];
    for (let i = 0; i < Math.min(limit, items.length); i++) {
        workers.push(worker());
    }

    await Promise.all(workers);
}
