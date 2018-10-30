from statistics import mean, median

f = open('hello-latency', 'r')
latencies = f.readlines()
f.close()

no_pyr = [l.split(',')[0].strip() for l in latencies]
no_pyr = list(map(float, no_pyr))
with_pyr = [l.split(',')[1].strip() for l in latencies]
with_pyr = list(map(float, with_pyr))

print("hello.py latency:")
print("min: %.2f us" % min(no_pyr))
print("median: %.2f us" % median(no_pyr))
print("mean: %.2f us" % mean(no_pyr))
print("max: %.2f us" % max(no_pyr))
print("")
print("hello.py latency with Pyronia:")
print("min: %.2f us" % min(with_pyr))
print("median: %.2f us" % median(with_pyr))
print("mean: %.2f us" % mean(with_pyr))
print("max: %.2f us" % max(with_pyr))
print("")
print("avg overhead: %dx" % int(float(mean(with_pyr))/float(mean(no_pyr))))
